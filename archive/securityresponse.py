import discord
from discord.ext import commands
from datetime import datetime, timedelta
import json
import configparser


config = configparser.RawConfigParser()
config.read('config.ini')

OWNER_ID = int(config['Users']['allowed'])


class SecurityResponse:
    def __init__(self):
        # Tracks attempts per user with timestamps
        self.attempts = {}
        # Tracks current warning level per user
        self.warning_levels = {}
        # Tracks user timeouts
        self.timeout_until = {}
        
        # Escalation configuration - Modified to be more strict
        self.ESCALATION_LEVELS = {
            # Level: (max_attempts, timeout_duration_minutes, action)
            1: (2, 5, "warn"),           # Warning after 2 attempts
            2: (3, 15, "timeout"),       # 15-min timeout after 3 attempts (1 more attempt)
            3: (4, 60, "long_timeout"),  # 1-hour timeout after 4 attempts (1 more attempt)
            4: (5, 1440, "ban")          # Server ban after 5 attempts (1 more attempt)
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
        print(f"Unauthorized attempt by {ctx.author} (Level {self.warning_levels[user_id]})")

    async def _apply_escalation(self, ctx, bot, level, timeout_mins, action):
        """Apply the appropriate escalation response"""
        user = ctx.author
        guild = ctx.guild
        
        if action == "warn":
            await user.send(
                f"⚠️ Warning (Level {level}): Unauthorized command attempts detected. "
                "Next attempt will result in a 15-minute timeout."
            )
            
        elif action == "timeout":
            self.timeout_until[user.id] = datetime.now() + timedelta(minutes=timeout_mins)
            await user.send(
                f"🚫 You have been timed out for {timeout_mins} minutes. "
                "Next attempt will result in a 1-hour timeout."
            )
            try:
                await user.timeout(duration=timedelta(minutes=timeout_mins))
            except discord.errors.Forbidden:
                print(f"Failed to timeout user {user.id} - Missing permissions")
                
        elif action == "long_timeout":
            self.timeout_until[user.id] = datetime.now() + timedelta(minutes=timeout_mins)
            await user.send(
                f"⛔ Extended timeout ({timeout_mins // 60} hours) applied. "
                "Next attempt will result in an immediate ban."
            )
            try:
                await user.timeout(duration=timedelta(minutes=timeout_mins))
            except discord.errors.Forbidden:
                print(f"Failed to timeout user {user.id} - Missing permissions")
                
        elif action == "ban":
            try:
                await guild.ban(
                    user,
                    reason="Excessive unauthorized bot command attempts",
                    delete_message_days=1
                )
                await user.send(
                    "🔨 You have been banned from the server due to excessive "
                    "unauthorized bot command attempts. Contact server administrators "
                    "if you believe this was in error."
                )
            except discord.errors.Forbidden:
                print(f"Failed to ban user {user.id} - Missing permissions")

class SecureBot(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        intents.voice_states = True
        intents.members = True
        super().__init__(command_prefix='!', intents=intents)
        self.security = SecurityResponse()

    async def check_authorization(self, ctx):
        """Check if user is authorized and handle unauthorized attempts"""
        if ctx.author.id != OWNER_ID:
            await self.security.handle_unauthorized_attempt(ctx, self)
            return False
        return True

# Example command using the security system
@bot.command()
async def test(ctx):
    if await bot.check_authorization(ctx):
        await ctx.send("Command executed successfully")