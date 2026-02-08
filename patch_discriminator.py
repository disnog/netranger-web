import re

with open('nrweb/discord.py', 'r') as f:
    content = f.read()

# Update display_name to handle None as well
old_display = '''@property
    def display_name(self) -> str:
        if self.discriminator and self.discriminator != "0":
            return f"{self.username}#{self.discriminator}"
        return self.username'''

new_display = '''@property
    def display_name(self) -> str:
        # Handle Discord's new username system (no discriminator) vs legacy
        if self.discriminator and self.discriminator not in ("0", "\"):
            return f"{self.username}#{self.discriminator}"
        return self.username'''

content = content.replace(old_display, new_display)

# Ensure discriminator default is handled correctly in get_user
old_get_user = '''return DiscordUser(
            id=data["id"],
            username=data["username"],
            discriminator=data.get("discriminator", "0"),
            avatar=data.get("avatar"),
            email=data.get("email"),
        )'''

new_get_user = '''return DiscordUser(
            id=data["id"],
            username=data["username"],
            discriminator=data.get("discriminator"),  # None for new system
            avatar=data.get("avatar"),
            email=data.get("email"),
        )'''

content = content.replace(old_get_user, new_get_user)

with open('nrweb/discord.py', 'w') as f:
    f.write(content)

print("Patched discord.py with better discriminator handling")
