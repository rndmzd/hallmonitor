import discord
from discord.ext import commands

# Bot token
TOKEN = 'your-bot-token-here'

# IDs for the specific voice channel and the General voice channel
SPECIFIC_VOICE_CHANNEL_ID = 123456789012345678  # Replace with your specific voice channel ID
GENERAL_VOICE_CHANNEL_ID = 876543210987654321   # Replace with your General voice channel ID

# IDs of designated users allowed in the specific channel
DESIGNATED_USER_IDS = [
    111111111111111111,  # Replace with designated user IDs
    222222222222222222,
    # Add more IDs as needed
]

intents = discord.Intents.default()
intents.voice_states = True  # Enable voice state intents
intents.members = True       # Enable member intents (if needed)

bot = commands.Bot(command_prefix='!', intents=intents)

@bot.event
async def on_voice_state_update(member, before, after):
    # Check if the user joined a new voice channel
    if before.channel != after.channel:
        # If the user joined the specific voice channel
        if after.channel and after.channel.id == SPECIFIC_VOICE_CHANNEL_ID:
            # If the user is not a designated user
            if member.id not in DESIGNATED_USER_IDS:
                # Find the General voice channel
                general_channel = discord.utils.get(member.guild.voice_channels, id=GENERAL_VOICE_CHANNEL_ID)
                if general_channel:
                    try:
                        # Move the member to the General voice channel
                        await member.move_to(general_channel)
                        print(f"Moved {member.name} to the General channel.")
                    except Exception as e:
                        print(f"Failed to move {member.name}: {e}")
                else:
                    print("General channel not found.")

# Run the bot
bot.run(TOKEN)
