import discord
from discord import app_commands
from discord.ext import commands
import requests
import re
import base64
import time
import asyncio
import socket

BOT_TOKEN = "BOT_TOKEN"
VT_API_KEY = "VIRUS_TOTAL_API_KEY"

intents = discord.Intents.default()
intents.message_content = True 
intents.members = True

bot = commands.Bot(intents=intents, command_prefix="unused_prefix")  

# ----------------------------------------------------------------
# Global Variables
# ----------------------------------------------------------------
scan_enabled = True
admin_channel_name = "admin-messages" # Can be changed via slash command
malicious_links_counter = 0
whitelisted_domains = set()

# ----------------------------------------------------------------
# VirusTotal & Utilities
# ----------------------------------------------------------------
def extract_urls(text):
    """Extract valid URLs starting with http or https."""
    url_pattern = r'(https?://[^\s]+)'
    return re.findall(url_pattern, text)

def force_virustotal_scan(url):
    """
    Force a fresh VirusTotal analysis by:
      1) POST /urls to request a new scan
      2) GET /analyses/{analysis_id} to see final results
    Returns (is_malicious, analysis_dict).
    """
    headers = {"x-apikey": VT_API_KEY}
    post_resp = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url}
    )
    if post_resp.status_code != 200:
        return False, {
            "error": f"POST failed: {post_resp.status_code}",
            "text": post_resp.text
        }

    post_data = post_resp.json()
    analysis_id = post_data.get("data", {}).get("id")
    if not analysis_id:
        return False, {"error": "No analysis ID from VirusTotal POST"}

    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    for _ in range(5):
        get_resp = requests.get(analysis_url, headers=headers)
        if get_resp.status_code == 200:
            get_data = get_resp.json()
            status = get_data.get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                stats = get_data.get("data", {}).get("attributes", {}).get("stats", {})
                malicious_count = stats.get("malicious", 0)
                suspicious_count = stats.get("suspicious", 0)
                is_malicious = (malicious_count > 0 or suspicious_count > 0)
                return is_malicious, {"status": status, "stats": stats}
        time.sleep(2)  # wait 2 seconds before next attempt

    return False, {"error": "Analysis not completed in time"}

def force_virustotal_file_scan(file_bytes):
    """Submit a file to VirusTotal for scanning."""
    headers = {"x-apikey": VT_API_KEY}
    files = {"file": ("attachment", file_bytes)}
    post_resp = requests.post(
        "https://www.virustotal.com/api/v3/files",
        headers=headers,
        files=files
    )
    if post_resp.status_code != 200:
        return False, {
            "error": f"POST failed: {post_resp.status_code}",
            "text": post_resp.text
        }

    post_data = post_resp.json()
    analysis_id = post_data.get("data", {}).get("id")
    if not analysis_id:
        return False, {"error": "No analysis ID from VirusTotal POST"}

    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    for _ in range(5):
        get_resp = requests.get(analysis_url, headers=headers)
        if get_resp.status_code == 200:
            get_data = get_resp.json()
            status = get_data.get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                stats = get_data.get("data", {}).get("attributes", {}).get("stats", {})
                malicious_count = stats.get("malicious", 0)
                suspicious_count = stats.get("suspicious", 0)
                is_malicious = (malicious_count > 0 or suspicious_count > 0)
                return is_malicious, {"status": status, "stats": stats}
        time.sleep(2)

    return False, {"error": "Analysis not completed in time"}

def get_domain_from_url(url: str):
    """Extract the domain from a URL."""
    try:
        if url.startswith("http://"):
            url = url[len("http://"):]
        elif url.startswith("https://"):
            url = url[len("https://"):]
        domain = url.split("/")[0]
        return domain.lower()
    except Exception:
        return url.lower()

# ----------------------------------------------------------------
# Bot Events
# ----------------------------------------------------------------
@bot.event
async def on_ready():
    print(f"Bot online as {bot.user}!")

    # IMPORTANT: Sync slash commands with Discord
    try:
        await bot.tree.sync()
        print("Slash commands synced.")
    except Exception as e:
        print(f"Error syncing slash commands: {e}")

    await bot.change_presence(activity=discord.Game(name="Monitoring Cyber Threats"))

@bot.event
async def on_message(message):
    """Scan messages for malicious URLs, same as before."""
    if message.author.bot:
        return

    # Malicious Link Checking (if enabled)
    if scan_enabled:
        urls = extract_urls(message.content)
        flagged = False

        for url in urls:
            domain = get_domain_from_url(url)
            if domain in whitelisted_domains:
                print(f"[DEBUG] Skipping whitelisted domain: {domain}")
                continue

            print(f"[DEBUG] Checking URL: {url}")
            is_malicious, analysis = force_virustotal_scan(url)
            print(f"[DEBUG] Analysis result: {analysis}")
            if is_malicious:
                flagged = True
                global malicious_links_counter
                malicious_links_counter += 1
                await message.delete()

        # Alert admin channel if flagged
        if flagged:
            admin_channel = discord.utils.get(
                message.guild.text_channels, name=admin_channel_name
            )
            if admin_channel:
                await admin_channel.send(
                    f"🚨 **Threat Detected**:\n"
                    f"User: {message.author}\n"
                    f"Content: {message.content}\n"
                    f"Channel: {message.channel.mention}"
                )
    await bot.process_commands(message)

# ----------------------------------------------------------------
# Slash Commands Section
# ----------------------------------------------------------------
# You define them with @bot.tree.command

@bot.tree.command(name="ping", description="Simple test to confirm the bot is responding.")
async def ping_command(interaction: discord.Interaction):
    await interaction.response.send_message("Online")

@bot.tree.command(name="togglescan", description="Toggle the scanning feature on/off.")
@app_commands.checks.has_permissions(administrator=True)
async def togglescan_command(interaction: discord.Interaction):
    global scan_enabled
    scan_enabled = not scan_enabled
    state = "enabled" if scan_enabled else "disabled"
    await interaction.response.send_message(f"URL scanning is now **{state}**.")

@bot.tree.command(name="setadminchannel", description="Set the channel name for threat alerts.")
@app_commands.describe(channel_name="The name of the channel to receive threat alerts.")
@app_commands.checks.has_permissions(administrator=True)
async def setadminchannel_command(interaction: discord.Interaction, channel_name: str):
    global admin_channel_name
    admin_channel_name = channel_name
    await interaction.response.send_message(f"Admin alert channel set to: #{channel_name}")

@bot.tree.command(name="stats", description="Show how many malicious links have been removed so far.")
async def stats_command(interaction: discord.Interaction):
    await interaction.response.send_message(
        f"I have removed **{malicious_links_counter}** malicious links so far."
    )

@bot.tree.command(name="cleanup", description="Delete the last N messages from the current channel.")
@app_commands.checks.has_permissions(administrator=True)
@app_commands.describe(num_messages="Number of messages to delete, default=5.")
async def cleanup_command(interaction: discord.Interaction, num_messages: int = 5):
    channel = interaction.channel
    if isinstance(channel, discord.TextChannel):
        deleted = await channel.purge(limit=num_messages)
        await interaction.response.send_message(f"Deleted {len(deleted)} messages.", ephemeral=True)
    else:
        await interaction.response.send_message("Cannot purge messages here.", ephemeral=True)

@bot.tree.command(name="whitelist", description="Add a domain to skip scanning.")
@app_commands.checks.has_permissions(administrator=True)
@app_commands.describe(domain="The domain to whitelist (e.g. example.com)")
async def whitelist_command(interaction: discord.Interaction, domain: str):
    domain = domain.lower()
    whitelisted_domains.add(domain)
    await interaction.response.send_message(f"Whitelisted domain: {domain}")

@bot.tree.command(name="unwhitelist", description="Remove a domain from the whitelist.")
@app_commands.checks.has_permissions(administrator=True)
@app_commands.describe(domain="The domain to remove from the whitelist.")
async def unwhitelist_command(interaction: discord.Interaction, domain: str):
    domain = domain.lower()
    if domain in whitelisted_domains:
        whitelisted_domains.remove(domain)
        await interaction.response.send_message(f"Removed whitelist for domain: {domain}")
    else:
        await interaction.response.send_message(f"Domain {domain} not found in whitelist.")

@bot.tree.command(name="showwhitelist", description="Show the current whitelisted domains.")
async def showwhitelist_command(interaction: discord.Interaction):
    if whitelisted_domains:
        domains_list = "\n".join(whitelisted_domains)
        await interaction.response.send_message(
            f"**Whitelisted Domains**:\n```\n{domains_list}\n```"
        )
    else:
        await interaction.response.send_message("No domains are whitelisted.")

@bot.tree.command(name="scanfile", description="Scan an attached file with VirusTotal.")
async def scanfile_command(interaction: discord.Interaction):

    await interaction.response.send_message(
        "File scanning via slash commands isn't straightforward. Use a bot action that receives an attachment in a normal channel message if possible.",
        ephemeral=True
    )

@bot.tree.command(name="whois", description="A simple whois-like command to check DNS info for a domain.")
@app_commands.describe(domain="Domain to look up, e.g. example.com")
async def whois_command(interaction: discord.Interaction, domain: str):
    domain = domain.lower()
    try:
        ip = socket.gethostbyname(domain)
        await interaction.response.send_message(f"**Domain**: {domain}\n**IP**: {ip}")
    except socket.gaierror:
        await interaction.response.send_message(f"Could not resolve {domain}.")

@bot.tree.command(name="kick", description="Kick a user from the server.")
@app_commands.checks.has_permissions(kick_members=True)
@app_commands.describe(
    member="The member to kick (mention or user ID).",
    reason="Reason for the kick."
)
async def kick_command(interaction: discord.Interaction, member: discord.Member, reason: str = "No reason provided"):
    if member == interaction.user:
        await interaction.response.send_message("You cannot kick yourself.", ephemeral=True)
        return
    await member.kick(reason=reason)
    await interaction.response.send_message(f"User {member.mention} kicked. Reason: {reason}")

@bot.tree.command(name="ban", description="Ban a user from the server.")
@app_commands.checks.has_permissions(ban_members=True)
@app_commands.describe(
    member="The member to ban (mention or user ID).",
    reason="Reason for the ban."
)
async def ban_command(interaction: discord.Interaction, member: discord.Member, reason: str = "No reason provided"):
    if member == interaction.user:
        await interaction.response.send_message("You cannot ban yourself.", ephemeral=True)
        return
    await member.ban(reason=reason)
    await interaction.response.send_message(f"User {member.mention} has been banned. Reason: {reason}")

@bot.tree.command(name="serverinfo", description="Display basic info about the server.")
async def serverinfo_command(interaction: discord.Interaction):
    guild = interaction.guild
    if guild is None:
        await interaction.response.send_message("This command can only be used in a server.")
        return

    embed = discord.Embed(title=guild.name, description="Server Info", color=0x00ff00)
    embed.add_field(name="Server ID", value=guild.id, inline=True)
    embed.add_field(name="Region", value=str(guild.region), inline=True)
    embed.add_field(name="Member Count", value=guild.member_count, inline=True)
    if guild.icon:
        embed.set_thumbnail(url=guild.icon.url)
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="userinfo", description="Display info about a user.")
@app_commands.describe(member="Which user to show info about; defaults to yourself.")
async def userinfo_command(interaction: discord.Interaction, member: discord.Member = None):
    if member is None:
        member = interaction.user

    embed = discord.Embed(title=str(member), description="User Info", color=0x00ff00)
    embed.add_field(name="ID", value=member.id, inline=True)
    embed.add_field(name="Status", value=str(member.status), inline=True)
    embed.add_field(name="Top Role", value=member.top_role.mention if member.top_role else "N/A", inline=True)
    if member.joined_at:
        embed.add_field(name="Joined", value=member.joined_at.strftime("%Y-%m-%d %H:%M:%S"), inline=False)
    if member.avatar:
        embed.set_thumbnail(url=member.avatar.url)
    await interaction.response.send_message(embed=embed)

# ----------------------------------------------------------------
# Run the Bot
# ----------------------------------------------------------------
def main():
    bot.run(BOT_TOKEN)

if __name__ == "__main__":
    main()
