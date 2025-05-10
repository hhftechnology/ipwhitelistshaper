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

## Features

- **Dynamic IP Whitelisting**: Temporarily whitelist IP addresses with automatic expiration
- **Admin Approval Flow**: Secure approval process with validation codes
- **File-Based State Storage**: Maintains state across multiple Traefik instances using persistent storage
- **Multiple Notification Options**: Support for Discord webhooks and other notification services
- **Smart Client IP Detection**: Support for X-Forwarded-For headers and configurable depth for proxy environments
- **Secure Token Generation**: HMAC-based token generation for approval links
- **Configurable Expiration**: Set how long approved IPs remain in the whitelist
- **Permanent Whitelisting**: Permanently whitelist specific IPs or networks
- **Pretty UI**: Clean HTML interface for users requesting access and admins approving requests

## Configuration

### Static Configuration

Enable the plugin in your Traefik static configuration:

```yaml
# Static configuration
experimental:
  plugins:
    ipwhitelistshaper:
      moduleName: github.com/hhftechnology/ipwhitelistshaper
      version: v1.0.3
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
          # Base URL for approval links
          approvalURL: "https://your-traefik-instance.example.com"
          
          # URL for notifications (e.g., Discord webhook)
          notificationURL: "https://discord.com/api/webhooks/your-webhook-id"
          
          # Default endpoint for requesting access
          knockEndpoint: "/knock-knock"
          
          # Allow private networks by default (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
          defaultPrivateClassSources: true
          
          # Configure how long (in seconds) an approved IP should remain in the whitelist
          expirationTime: 300
          
          # Depth to look into X-Forwarded-For header (set to 1 if behind CloudFlare or another proxy)
          ipStrategyDepth: 0
          
          # IPs to exclude from X-Forwarded-For processing
          excludedIPs: []
          
          # Permanently whitelisted IPs (in addition to defaults)
          whitelistedIPs: []
          
          # Secret key for secure token generation (auto-generated if not provided)
          secretKey: ""
          
          # File-based storage configuration
          storageEnabled: true
          storagePath: "/plugins-storage/ipwhitelistshaper"
          saveInterval: 30  # Save every 30 seconds
```

## File-Based Storage

This plugin now includes a file-based storage system to maintain state across Traefik instances and restarts. This ensures that approval tokens and whitelisted IPs remain valid even when Traefik instances are restarted or when requests are handled by different instances.

### How File Storage Works

1. **Persistent State**: The plugin periodically saves its state to disk, including:
   - Currently whitelisted IPs and their expiration times
   - Pending approval requests and their tokens
   - Last request times for rate limiting

2. **Automatic Recovery**: When the plugin starts, it automatically loads the previously saved state from disk

3. **Concurrent Safety**: The storage system is designed to be thread-safe and handles concurrent access properly

### Storage Configuration

You can configure the storage system with these parameters:

- `storageEnabled`: Enable or disable file-based storage (default: true)
- `storagePath`: Directory where state files will be stored (default: "/plugins-storage/ipwhitelistshaper")
- `saveInterval`: How often to save state to disk in seconds (default: 30)

### Volume Mounting

To use file-based storage with Docker, you need to mount a volume to the storage path:

```yaml
volumes:
  - ./traefik/plugins-storage:/plugins-storage:rw
```

This ensures that the storage directory is persistent and accessible to Traefik.

## Example Router Configuration

Apply the middleware to your HTTP routers to protect your services:

```yaml
http:
  routers:
    # Main router that applies the whitelist protection
    protected-service:
      rule: "Host(`service.example.com`)"
      service: "my-service"
      middlewares:
        - "my-ipwhitelistshaper"
    
    # Special router to handle the knock-knock endpoint
    knock-knock-router:
      rule: "Host(`service.example.com`) && Path(`/knock-knock`)"
      service: "my-service"
      middlewares:
        - "my-ipwhitelistshaper"
      priority: 110  # Higher priority than the main router
      
    # Special router to handle the approval endpoint
    approve-router:
      rule: "Host(`service.example.com`) && PathPrefix(`/approve/`)"
      service: "my-service"
      middlewares:
        - "my-ipwhitelistshaper"
      priority: 110  # Higher priority than the main router
```

> **Important:** You must define separate routers for the knock-knock and approve endpoints with higher priority than your main router. This ensures that these special paths are correctly handled by the middleware.

## Notifications

The plugin sends two types of notifications:

1. **Access Request Notifications**: When a user visits the knock-knock endpoint, a notification is sent with their IP, a validation code, and an approval link.
2. **Status Notifications**: When an IP is approved or expires.

### Discord Webhook Integration

To use Discord for notifications:

1. Create a webhook in your Discord server (Server Settings → Integrations → Webhooks)
2. Copy the webhook URL
3. Add it to your configuration:

```yaml
ipwhitelistshaper:
  notificationURL: "https://discord.com/api/webhooks/your-webhook-id/your-webhook-token"
```

The plugin automatically detects Discord webhook URLs and formats messages appropriately.

### Other Notification Services

For other webhook-based notification services, simply provide the webhook URL:

```yaml
ipwhitelistshaper:
  notificationURL: "https://your-notification-service.example.com/webhook"
```

Messages are sent with a `message` parameter in the request body.

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
## For Middleware-manager
```yaml
  - id: "ipwhitelistshaper"
    name: "IP Whitelist Shaper"
    type: "plugin"
    config:
      ipwhitelistshaper:
        knockEndpoint: "/knock-knock"
        approvalURL: "https://wallos.development.hhf.technology"
        notificationURL: "https://discord.com/api/webhooks/"
        defaultPrivateClassSources: true
        expirationTime: 300
        ipStrategyDepth: 0
        secretKey: ""
        excludedIPs: []
        whitelistedIPs:
          - "127.0.0.1/32"
          - "192.168.1.0/24"
          - "10.0.0.0/8"
        storageEnabled: true
        storagePath: "/plugins-storage/ipwhitelistshaper"
        saveInterval: 30
```
```yaml
providers:
  http:
    endpoint: "http://pangolin:3001/api/v1/traefik-config"
    pollInterval: "5s"
  file:
    directory: "/rules"
    watch: true

experimental:
  plugins:
    badger:
      moduleName: "github.com/fosrl/badger"
      version: "v1.1.0"
  localPlugins:
    ipwhitelistshaper:
      moduleName: "github.com/hhftechnology/ipwhitelistshaper"
```
```yaml
  traefik:
    image: traefik:v3.3.3
    container_name: traefik
    restart: unless-stopped

    network_mode: service:gerbil # Ports appear on the gerbil service

    depends_on:
      pangolin:
        condition: service_healthy
    command:
      - --configFile=/etc/traefik/traefik_config.yml
    volumes:
      - ./config/traefik:/etc/traefik:ro # Volume to store the Traefik configuration
      - ./config/letsencrypt:/letsencrypt # Volume to store the Let's Encrypt certificates
      - ./config/traefik/logs:/var/log/traefik # Volume to store Traefik logs
      - ./traefik/plugins-storage:/plugins-storage:rw
      - ./traefik/plugins-storage:/plugins-local:rw
      - ./config/traefik/rules:/rules
```
>[!Tip]
> I just loved the creation by l4rm4nd and i build a Traefik plugin around this idea. Original idea check it out [here](https://github.com/l4rm4nd/TraefikShaper/).

## Troubleshooting

### Token Validation Errors

If you're seeing "Invalid token or IP address" errors when clicking approval links:

1. Check that your storage directory has proper permissions (read/write for Traefik)
2. Verify that `storagePath` is set correctly and consistent across all instances
3. Check Traefik logs for any storage-related errors
4. Ensure that your `approve-router` is correctly configured in your Traefik config

### Missing Notifications

If notifications aren't being sent:

1. Check that your `notificationURL` is correct
2. For Discord, ensure the webhook URL includes both the webhook ID and token
3. Check Traefik logs for any webhook errors

### Storage Issues

If state is not being properly maintained:

1. Check if the storage directory exists and has correct permissions
2. Look for errors related to file operations in the Traefik logs
3. Verify that the storage volume is properly mounted if using Docker
4. Try increasing the `saveInterval` to reduce disk operations

## License

```
