import configparser
import discord
from discord.ext import commands

config = configparser.ConfigParser()
config.read('config.ini')

# Bot configuration
TOKEN = 'YOUR_BOT_TOKEN'
MONITORED_CHANNEL_ID = 123456789  # Replace with your channel ID
GENERAL_CHANNEL_ID = 987654321    # Replace with your general channel ID
OWNER_ID = 444444444             # Replace with YOUR user ID
ALLOWED_USER_IDS = [              # Replace with allowed user IDs
    111111111,
    222222222,
    333333333
]

# Create bot instance
intents = discord.Intents.default()
intents.voice_states = True
intents.members = True
bot = commands.Bot(command_prefix='!', intents=intents)

# Custom check for owner
def is_owner():
    async def predicate(ctx):
        return ctx.author.id == OWNER_ID
    return commands.check(predicate)

@bot.event
async def on_ready():
    """Event handler for when the bot starts up"""
    print(f'{bot.user} has connected to Discord!')
    print('Monitoring voice channel...')
    print(f'Bot will only respond to user ID: {OWNER_ID}')

@bot.event
async def on_voice_state_update(member, before, after):
    """Event handler for voice channel changes"""
    # Check if someone joined the monitored channel
    if after and after.channel and after.channel.id == MONITORED_CHANNEL_ID:
        # If user is not in allowed list, move them to general
        if member.id not in ALLOWED_USER_IDS:
            try:
                general_channel = bot.get_channel(GENERAL_CHANNEL_ID)
                await member.move_to(general_channel)
                print(f'Moved {member.name} to general channel')
                
                # Optional: Send a DM to the user explaining why they were moved
                try:
                    await member.send(
                        "You've been moved to the general channel as you don't "
                        "have permission to join the restricted voice channel."
                    )
                except discord.errors.Forbidden:
                    print(f"Couldn't send DM to {member.name}")
                    
            except discord.errors.Forbidden:
                print(f"Missing permissions to move {member.name}")
            except Exception as e:
                print(f"Error moving {member.name}: {str(e)}")

@bot.command()
@is_owner()
async def allow(ctx, user_id: int):
    """Add a user to the allowed list"""
    if user_id not in ALLOWED_USER_IDS:
        ALLOWED_USER_IDS.append(user_id)
        await ctx.send(f"User {user_id} added to allowed list.")
    else:
        await ctx.send("User is already in the allowed list.")

@bot.command()
@is_owner()
async def remove(ctx, user_id: int):
    """Remove a user from the allowed list"""
    if user_id in ALLOWED_USER_IDS:
        ALLOWED_USER_IDS.remove(user_id)
        await ctx.send(f"User {user_id} removed from allowed list.")
    else:
        await ctx.send("User is not in the allowed list.")

@bot.command()
@is_owner()
async def listallowed(ctx):
    """List all allowed users"""
    if ALLOWED_USER_IDS:
        allowed_users = "\n".join([str(uid) for uid in ALLOWED_USER_IDS])
        await ctx.send(f"Allowed users:\n{allowed_users}")
    else:
        await ctx.send("No users in allowed list.")

@bot.event
async def on_command_error(ctx, error):
    """Handle command errors"""
    if isinstance(error, commands.CheckFailure):
        # Silently ignore commands from unauthorized users
        pass
    else:
        print(f"Error: {str(error)}")

# Start the bot
bot.run(TOKEN)