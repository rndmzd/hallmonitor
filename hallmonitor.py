import discord
from discord.ext import commands
import logging
from datetime import datetime, timedelta
import time
import configparser

# Read configuration from config.ini
config = configparser.RawConfigParser()
config.read('config.ini')

# Bot configuration
TOKEN = config['Bot']['token']
MONITORED_CHANNEL_ID = int(config['Channels']['monitored'])
GENERAL_CHANNEL_ID = int(config['Channels']['removal_destination'])
OWNER_ID = int(config['Users']['owner'])
ALLOWED_USER_IDS = [int(usr.strip()) for usr in config['Users']['allowed'].split(',')]

# Security configuration
MAX_FAILED_ATTEMPTS = int(config['Security']['max_failed_attempts'])
LOCKOUT_DURATION = int(config['Security']['lockout_duration'])
NOTIFY_ON_UNAUTHORIZED = config.getboolean('Security', 'notify_on_unauthorized')
LOG_FILE = config['General']['log_file']
LOG_CHANNEL_ID = config.getint('Security', 'log_channel_id', fallback=None)

# Set up logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class SecurityResponse:
    def __init__(self):
        # Tracks attempts per user with timestamps
        self.attempts = {}
        # Tracks current warning level per user
        self.warning_levels = {}
        # Tracks user timeouts
        self.timeout_until = {}
        
        # Escalation configuration
        self.ESCALATION_LEVELS = {
            # Level: (max_attempts, timeout_duration_minutes, action)
            1: (2, 5, "warn"),           # Warning after 2 attempts
            2: (3, 15, "timeout"),       # 15-min timeout after 3 attempts
            3: (4, 60, "long_timeout"),  # 1-hour timeout after 4 attempts
            4: (5, 1440, "ban")          # Ban after 5 attempts
        }
        
        # Time window for tracking attempts (24 hours)
        self.ATTEMPT_WINDOW = timedelta(hours=24)

    async def handle_unauthorized_attempt(self, ctx, bot):
        """Handle unauthorized command attempt with escalating responses"""
        user_id = ctx.author.id
        current_time = datetime.now()
        
        # Initialize tracking for new users
        if user_id not in self.attempts:
            self.attempts[user_id] = []
            self.warning_levels[user_id] = 0
            
        # Clean up old attempts outside the window
        self.attempts[user_id] = [
            timestamp for timestamp in self.attempts[user_id]
            if current_time - timestamp < self.ATTEMPT_WINDOW
        ]
        
        # Add new attempt
        self.attempts[user_id].append(current_time)
        
        # Check if user is in timeout
        if user_id in self.timeout_until:
            if current_time < self.timeout_until[user_id]:
                remaining_time = (self.timeout_until[user_id] - current_time)
                if NOTIFY_ON_UNAUTHORIZED:
                    await ctx.author.send(
                        f"You are in timeout for {remaining_time.seconds // 60} more minutes. "
                        "Further attempts will result in increased restrictions."
                    )
                return
            else:
                del self.timeout_until[user_id]
        
        # Determine appropriate escalation level
        attempt_count = len(self.attempts[user_id])
        
        for level, (max_attempts, timeout_mins, action) in self.ESCALATION_LEVELS.items():
            if attempt_count >= max_attempts and self.warning_levels[user_id] < level:
                self.warning_levels[user_id] = level
                await self._apply_escalation(ctx, bot, level, timeout_mins, action)
                break
                
        # Log the attempt
        await bot.log_security_event(
            "UNAUTHORIZED_ATTEMPT",
            user_id,
            f"Attempted command: {ctx.command} (Level {self.warning_levels[user_id]})"
        )

    async def _apply_escalation(self, ctx, bot, level, timeout_mins, action):
        """Apply the appropriate escalation response"""
        user = ctx.author
        guild = ctx.guild

        if action == "warn":
            if NOTIFY_ON_UNAUTHORIZED:
                await user.send(
                    f"⚠️ Warning (Level {level}): Unauthorized command attempts detected. "
                    "Further attempts will result in increased restrictions."
                )
                
        elif action == "timeout":
            self.timeout_until[user.id] = datetime.now() + timedelta(minutes=timeout_mins)
            if NOTIFY_ON_UNAUTHORIZED:
                await user.send(
                    f"🚫 You have been timed out for {timeout_mins} minutes. "
                    "Please refrain from unauthorized actions."
                )
            try:
                await user.timeout(timedelta(minutes=timeout_mins), reason="Unauthorized command attempts")
            except discord.errors.Forbidden:
                await bot.log_security_event(
                    "ERROR",
                    user.id,
                    f"Failed to timeout user - Missing permissions"
                )
                    
        elif action == "long_timeout":
            self.timeout_until[user.id] = datetime.now() + timedelta(minutes=timeout_mins)
            if NOTIFY_ON_UNAUTHORIZED:
                await user.send(
                    f"⛔ Extended timeout ({timeout_mins // 60} hours) applied. "
                    "Continued attempts will result in a ban."
                )
            try:
                await user.timeout(timedelta(minutes=timeout_mins), reason="Unauthorized command attempts")
            except discord.errors.Forbidden:
                await bot.log_security_event(
                    "ERROR",
                    user.id,
                    f"Failed to timeout user - Missing permissions"
                )
                    
        elif action == "ban":
            try:
                await guild.ban(
                    user,
                    reason="Excessive unauthorized bot command attempts",
                    delete_message_days=1
                )
                if NOTIFY_ON_UNAUTHORIZED:
                    await user.send(
                        "🔨 You have been banned from the server due to excessive "
                        "unauthorized bot command attempts. Contact server administrators "
                        "if you believe this was in error."
                    )
                await bot.log_security_event(
                    "BAN",
                    user.id,
                    "User has been banned due to unauthorized attempts"
                )
            except discord.errors.Forbidden:
                await bot.log_security_event(
                    "ERROR",
                    user.id,
                    f"Failed to ban user - Missing permissions"
                )

class SecureBot(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        intents.voice_states = True
        intents.members = True
        super().__init__(command_prefix='!', intents=intents)
        self.security = SecurityResponse()

    async def log_security_event(self, event_type, user_id, details):
        """Log security events to file and Discord channel"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"{timestamp} - {event_type} - User: {user_id} - {details}"
        
        # Log to file
        logging.info(log_message)
        
        # Log to Discord channel
        if LOG_CHANNEL_ID:
            channel = self.get_channel(LOG_CHANNEL_ID)
            if channel:
                await channel.send(f"```\n{log_message}\n```")

    async def check_authorization(self, ctx):
        """Check if user is authorized and handle unauthorized attempts"""
        user_id = ctx.author.id

        # Owner is always authorized
        if user_id == OWNER_ID:
            await self.log_security_event(
                "AUTHORIZED_COMMAND",
                user_id,
                f"Executed command: {ctx.command}"
            )
            return True

        # Check if user is in timeout
        if user_id in self.security.timeout_until:
            if datetime.now() < self.security.timeout_until[user_id]:
                remaining_time = self.security.timeout_until[user_id] - datetime.now()
                await self.log_security_event(
                    "BLOCKED_ATTEMPT",
                    user_id,
                    f"Attempted command while in timeout: {ctx.command}"
                )
                if NOTIFY_ON_UNAUTHORIZED:
                    await ctx.author.send(
                        f"You are in timeout for {remaining_time.seconds // 60} more minutes."
                    )
                return False
            else:
                # Timeout expired
                del self.security.timeout_until[user_id]

        # Check if user is allowed
        if user_id in ALLOWED_USER_IDS:
            await self.log_security_event(
                "AUTHORIZED_COMMAND",
                user_id,
                f"Executed command: {ctx.command}"
            )
            return True
        else:
            # Unauthorized attempt
            await self.security.handle_unauthorized_attempt(ctx, self)
            return False

bot = SecureBot()

@bot.event
async def on_ready():
    """Event handler for when the bot starts up"""
    print(f'{bot.user} has connected to Discord!')
    await bot.log_security_event("STARTUP", bot.user.id, "Bot initialized")

@bot.event
async def on_voice_state_update(member, before, after):
    """Event handler for voice channel changes"""
    # Check if the user joined a new voice channel
    if before.channel != after.channel:
        # If the user joined the monitored voice channel
        if after.channel and after.channel.id == MONITORED_CHANNEL_ID:
            # If the user is not allowed
            if member.id not in ALLOWED_USER_IDS:
                general_channel = bot.get_channel(GENERAL_CHANNEL_ID)
                if general_channel:
                    try:
                        await member.move_to(general_channel)
                        await bot.log_security_event(
                            "CHANNEL_ENFORCEMENT",
                            member.id,
                            f"Moved unauthorized user from monitored channel"
                        )
                        if NOTIFY_ON_UNAUTHORIZED:
                            try:
                                await member.send(
                                    "You've been moved to the general channel as you don't "
                                    "have permission to join the restricted voice channel."
                                )
                            except discord.errors.Forbidden:
                                # User has DMs closed
                                pass
                    except Exception as e:
                        await bot.log_security_event(
                            "ERROR",
                            member.id,
                            f"Error moving user: {str(e)}"
                        )
                else:
                    await bot.log_security_event(
                        "ERROR",
                        bot.user.id,
                        "General channel not found"
                    )

@bot.command()
async def allow(ctx, user_id: int):
    """Add a user to the allowed list"""
    if await bot.check_authorization(ctx):
        if user_id not in ALLOWED_USER_IDS:
            ALLOWED_USER_IDS.append(user_id)
            await ctx.send(f"User {user_id} added to allowed list.")
            await bot.log_security_event(
                "USER_ALLOWED",
                ctx.author.id,
                f"Added user {user_id} to allowed list"
            )
        else:
            await ctx.send("User is already in the allowed list.")

@bot.command()
async def remove(ctx, user_id: int):
    """Remove a user from the allowed list"""
    if await bot.check_authorization(ctx):
        if user_id in ALLOWED_USER_IDS:
            ALLOWED_USER_IDS.remove(user_id)
            await ctx.send(f"User {user_id} removed from allowed list.")
            await bot.log_security_event(
                "USER_REMOVED",
                ctx.author.id,
                f"Removed user {user_id} from allowed list"
            )
        else:
            await ctx.send("User is not in the allowed list.")

@bot.command()
async def listallowed(ctx):
    """List all allowed users"""
    if await bot.check_authorization(ctx):
        if ALLOWED_USER_IDS:
            allowed_users = "\n".join([str(uid) for uid in ALLOWED_USER_IDS])
            await ctx.send(f"Allowed users:\n{allowed_users}")
        else:
            await ctx.send("No users in allowed list.")

@bot.command()
async def security_status(ctx):
    """View current security status"""
    if await bot.check_authorization(ctx):
        locked_users_info = "\n".join([
            f"User {uid}: Locked until {time.strftime('%H:%M:%S', time.localtime(lock_time.timestamp()))}"
            for uid, lock_time in bot.security.timeout_until.items()
        ])
        failed_attempts_info = "\n".join([
            f"User {uid}: {len(attempts)} attempts"
            for uid, attempts in bot.security.attempts.items()
        ])
        
        await ctx.send(f"""Security Status:
Locked Users:
{locked_users_info or 'None'}

Failed Attempts:
{failed_attempts_info or 'None'}
""")

# Run the bot
bot.run(TOKEN)
