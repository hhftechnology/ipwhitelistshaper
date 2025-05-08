# Traefik IP Whitelist Shaper

<div align="center" width="100%">
    <p>A Traefik middleware plugin for dynamic IP whitelisting with administrator approval flow</p>
    <a target="_blank" href="https://github.com/hhftechnology/ipwhitelistshaper"><img src="https://img.shields.io/badge/maintainer-hhftechnology-orange" /></a>
</div>

## How It Works

This Traefik plugin provides a dynamic IP whitelisting mechanism with an admin approval flow. When a user tries to access a protected service and is not in the whitelist, they can request temporary access through a special endpoint. An administrator receives a notification with an approval link that can whitelist the user's IP for a configurable amount of time.

The flow works as follows:

1. User tries to access a protected service → gets 403 Forbidden response
2. User visits the knock-knock endpoint (e.g., `/knock-knock`) to request access
3. Admin receives a notification with the user's IP, a random validation code, and an approval link
4. Admin verifies the user (using the validation code) and clicks the approval link
5. User's IP is whitelisted for a limited time period
6. After the time period expires, the IP is automatically removed from the whitelist

## Configuration

### Static Configuration

Enable the plugin in your Traefik static configuration:

```yaml
# Static configuration
experimental:
  plugins:
    ipwhitelistshaper:
      moduleName: github.com/hhftechnology/ipwhitelistshaper
      version: v0.1.0
```

### Dynamic Configuration

Configure the middleware in your dynamic configuration:

```yaml
# Dynamic configuration
http:
  middlewares:
    my-ipwhitelistshaper:
      plugin:
        ipwhitelistshaper:
          # Default endpoint for requesting access
          knockEndpoint: "/knock-knock"
          
          # Allow private networks by default (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
          defaultPrivateClassSources: true
          
          # Configure how long (in seconds) an approved IP should remain in the whitelist
          expirationTime: 300
          
          # Depth to look into X-Forwarded-For header (set to 1 if behind CloudFlare or another proxy)
          ipStrategyDepth: 0
          
          # IPs to exclude from X-Forwarded-For processing (comma-separated)
          excludedIPs: []
          
          # Permanently whitelisted IPs (in addition to defaults)
          whitelistedIPs: []
          
          # Secret key for secure token generation (auto-generated if not provided)
          secretKey: ""
          
          # URL for notifications (HTTP POST will be made with "message" parameter)
          notificationURL: "https://yourwebhook.example.com/notify"
          
          # Base URL for approval links (defaults to the request host if not specified)
          approvalURL: "https://traefik.example.com"
```

## Example Router Configuration

Apply the middleware to your HTTP routers to protect your services:

```yaml
http:
  routers:
    protected-service:
      rule: "Host(`service.example.com`)"
      service: "my-service"
      middlewares:
        - "my-ipwhitelistshaper"
    
    # Special router to handle the knock-knock endpoint
    knock-endpoint:
      rule: "Host(`service.example.com`) && Path(`/knock-knock`)"
      service: "my-service"
      middlewares:
        - "my-ipwhitelistshaper"
```

## Notifications

The plugin sends two types of notifications:

1. **Access Request Notifications**: When a user visits the knock-knock endpoint, a notification is sent with their IP, a validation code, and an approval link.
2. **Status Notifications**: When an IP is approved or expires.

You can configure a notification URL to receive these updates. The plugin will make HTTP POST requests to this URL with a "message" parameter containing the notification text.

For more sophisticated notifications, you can set up a webhook receiver that forwards these messages to your preferred notification channel (Slack, Telegram, email, etc.).

## Comparison with Original TraefikShaper

This plugin is based on the original [TraefikShaper](https://github.com/l4rm4nd/TraefikShaper) project, but has been redesigned as a native Traefik plugin. Key differences:

1. **Native Integration**: Runs directly within Traefik instead of requiring a separate container
2. **Language**: Written in Go instead of Python
3. **Storage**: Uses in-memory data structures instead of manipulating config files
4. **Notifications**: Simplified notification system through webhooks

## Usage Behind a Proxy (like CloudFlare)

If your Traefik instance runs behind another proxy (like CloudFlare), you'll need to adjust the IP strategy to correctly identify client IPs:

```yaml
ipwhitelistshaper:
  # Use depth 1 to get the client IP from X-Forwarded-For when behind one proxy
  ipStrategyDepth: 1
```

Or alternatively, use the excludedIPs strategy:

```yaml
ipwhitelistshaper:
  # Exclude CloudFlare IPs from X-Forwarded-For processing
  excludedIPs:
    - "103.21.244.0/22"
    - "103.22.200.0/22"
    # Add more CloudFlare IP ranges
```

## Building and Testing

This plugin can be tested locally using the Traefik plugin local mode:

1. Clone this repository
2. Place it in the `./plugins-local/src/github.com/hhftechnology/ipwhitelistshaper` directory
3. Enable local plugins in your Traefik configuration

## License

MIT License