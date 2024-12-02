import configparser
import discord
from discord.ext import commands
import logging
import json
from datetime import datetime, timedelta
import asyncio

config = configparser.RawConfigParser()
config.read('config.ini')

# Bot configuration
TOKEN = config['Bot']['token']
MONITORED_CHANNEL_ID = int(config['Channels']['monitored'])
GENERAL_CHANNEL_ID = int(config['Channels']['removal_destination'])
OWNER_ID = int(config['Users']['allowed'])
LOG_CHANNEL_ID = 555555555  # Channel for logging security events
ALLOWED_USER_IDS = [111111111, 222222222, 333333333]

# Security configuration
MAX_FAILED_ATTEMPTS = 3
LOCKOUT_DURATION = 300  # seconds
NOTIFY_ON_UNAUTHORIZED = True
LOG_FILE = 'security_log.txt'

class SecurityBot(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        intents.voice_states = True
        intents.members = True
        super().__init__(command_prefix='!', intents=intents)
        
        # Initialize security tracking
        self.failed_attempts = {}
        self.locked_users = {}
        self.command_history = []
        
        # Set up logging
        logging.basicConfig(
            filename=LOG_FILE,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
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
        """Enhanced authorization check with rate limiting and lockouts"""
        user_id = ctx.author.id
        
        # Check if user is locked out
        if user_id in self.locked_users:
            if datetime.now() < self.locked_users[user_id]:
                remaining_time = (self.locked_users[user_id] - datetime.now()).seconds
                await self.log_security_event(
                    "BLOCKED_ATTEMPT",
                    user_id,
                    f"Attempted command while locked out: {ctx.command}"
                )
                if NOTIFY_ON_UNAUTHORIZED:
                    await ctx.author.send(
                        f"You are temporarily locked out for {remaining_time} more seconds."
                    )
                return False
            else:
                del self.locked_users[user_id]
                self.failed_attempts[user_id] = 0
        
        # Owner check
        if user_id != OWNER_ID:
            # Track failed attempts
            self.failed_attempts[user_id] = self.failed_attempts.get(user_id, 0) + 1
            
            if self.failed_attempts[user_id] >= MAX_FAILED_ATTEMPTS:
                # Lock out user
                self.locked_users[user_id] = datetime.now() + timedelta(seconds=LOCKOUT_DURATION)
                await self.log_security_event(
                    "LOCKOUT",
                    user_id,
                    f"User locked out after {MAX_FAILED_ATTEMPTS} failed attempts"
                )
                if NOTIFY_ON_UNAUTHORIZED:
                    await ctx.author.send(
                        f"You have been temporarily locked out for {LOCKOUT_DURATION} seconds "
                        "due to too many unauthorized attempts."
                    )
            else:
                await self.log_security_event(
                    "UNAUTHORIZED_ATTEMPT",
                    user_id,
                    f"Attempted command: {ctx.command}"
                )
                if NOTIFY_ON_UNAUTHORIZED:
                    await ctx.author.send(
                        "You are not authorized to use this command. "
                        f"Warning {self.failed_attempts[user_id]}/{MAX_FAILED_ATTEMPTS}"
                    )
            return False
            
        # Log successful owner command
        await self.log_security_event(
            "AUTHORIZED_COMMAND",
            user_id,
            f"Executed command: {ctx.command}"
        )
        return True

bot = SecurityBot()

@bot.event
async def on_ready():
    """Event handler for when the bot starts up"""
    print(f'{bot.user} has connected to Discord!')
    await bot.log_security_event("STARTUP", bot.user.id, "Bot initialized")

@bot.event
async def on_voice_state_update(member, before, after):
    """Event handler for voice channel changes"""
    if after and after.channel and after.channel.id == MONITORED_CHANNEL_ID:
        if member.id not in ALLOWED_USER_IDS:
            try:
                general_channel = bot.get_channel(GENERAL_CHANNEL_ID)
                await member.move_to(general_channel)
                await bot.log_security_event(
                    "CHANNEL_ENFORCEMENT",
                    member.id,
                    f"Moved unauthorized user from monitored channel"
                )
                
                try:
                    await member.send(
                        "You've been moved to the general channel as you don't "
                        "have permission to join the restricted voice channel."
                    )
                except discord.errors.Forbidden:
                    pass
                    
            except Exception as e:
                await bot.log_security_event(
                    "ERROR",
                    member.id,
                    f"Error moving user: {str(e)}"
                )

@bot.command()
async def allow(ctx, user_id: int):
    """Add a user to the allowed list"""
    if await bot.check_authorization(ctx):
        if user_id not in ALLOWED_USER_IDS:
            ALLOWED_USER_IDS.append(user_id)
            await ctx.send(f"User {user_id} added to allowed list.")
        else:
            await ctx.send("User is already in the allowed list.")

@bot.command()
async def remove(ctx, user_id: int):
    """Remove a user from the allowed list"""
    if await bot.check_authorization(ctx):
        if user_id in ALLOWED_USER_IDS:
            ALLOWED_USER_IDS.remove(user_id)
            await ctx.send(f"User {user_id} removed from allowed list.")
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
            f"User {uid}: Locked until {time.strftime('%H:%M:%S')}"
            for uid, time in bot.locked_users.items()
        ])
        failed_attempts_info = "\n".join([
            f"User {uid}: {attempts} attempts"
            for uid, attempts in bot.failed_attempts.items()
        ])
        
        await ctx.send(f"""Security Status:
Locked Users:
{locked_users_info or 'None'}

Failed Attempts:
{failed_attempts_info or 'None'}
""")

bot.run(TOKEN)