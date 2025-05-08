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
- **Multiple Notification Options**: Support for Discord webhooks and other notification services
- **Distributed State Management**: Redis integration for reliable operation in clustered environments
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
      version: v1.0.0
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
          
          # Redis configuration for distributed deployments
          redisEnabled: true
          redisAddress: "redis:6379"
          redisPassword: ""
          redisDB: 0
          redisKeyPrefix: "ipwhitelistshaper:"
```

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
      rule: "Host(`service.example.com`) && PathPrefix(`/approve`)"
      service: "my-service"
      middlewares:
        - "my-ipwhitelistshaper"
      priority: 110  # Higher priority than the main router
```

> **Important:** You must define separate routers for the knock-knock and approve endpoints with higher priority than your main router. This ensures that these special paths are correctly handled by the middleware.

## Distributed Deployment with Redis

For production environments with multiple Traefik instances, you should enable Redis support to ensure all instances share the same state:

```yaml
ipwhitelistshaper:
  redisEnabled: true
  redisAddress: "redis:6379"
  redisPassword: "your-redis-password"
  redisDB: 0
  redisKeyPrefix: "ipwhitelistshaper:"
```

This ensures that:
- Approval tokens generated by one instance are recognized by all instances
- IP whitelists are shared across all Traefik instances
- Expiration times are properly synchronized

Redis keys are automatically cleaned up when they expire, minimizing resource usage.

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

## Troubleshooting

### Token Validation Errors

If you're seeing "Invalid token or IP address" errors when clicking approval links:

1. Make sure you have Redis enabled if running multiple Traefik instances
2. Check that your approval links have the correct host and scheme
3. Verify that the `approve-router` is correctly configured in your Traefik config

### Missing Notifications

If notifications aren't being sent:

1. Check that your `notificationURL` is correct
2. For Discord, ensure the webhook URL includes both the webhook ID and token
3. Check Traefik logs for any webhook errors

### IP Detection Issues

If the wrong IP is being used for whitelist checks:

1. Adjust the `ipStrategyDepth` setting to match your proxy configuration
2. Set up `excludedIPs` if using proxy services like CloudFlare
3. Test with a service that displays the client IP to verify correct detection

## License

Apache License 2.0

# Adding Redis to Your Pangolin Setup

To integrate Redis with your IPWhitelistShaper plugin in your Pangolin infrastructure, follow these steps:

## 1. Add Redis Service to Docker Compose

Add the Redis service to your existing `docker-compose.yml` file:

```yaml
services:
  pangolin:
    # existing configuration...
  
  gerbil:
    # existing configuration...
  
  traefik:
    # existing configuration...
  
  middleware-manager:
    # existing configuration...
    
  error-pages:
    # existing configuration...
    
  # Add Redis service
  redis:
    image: redis:7-alpine
    container_name: redis
    restart: unless-stopped
    command: redis-server --appendonly yes --requirepass "${REDIS_PASSWORD:-changeme}"
    volumes:
      - ./data/redis:/data
    healthcheck:
      test: ["CMD", "redis-cli", "--raw", "ping"]
      interval: 5s
      timeout: 5s
      retries: 5
    networks:
      - default
    environment:
      - TZ=UTC
```

## 2. Configure Environment Variables

Create or update your `.env` file to include Redis password:

```
REDIS_PASSWORD=your_secure_password_here
```

## 3. Update Middleware Manager Template

Add the IPWhitelistShaper middleware template with Redis configuration to your `templates.yaml` file in the middleware manager:

```yaml
  - id: "ipwhitelistshaper"
    name: "IP Whitelist Shaper"
    type: "plugin"
    config:
      ipwhitelistshaper:
        knockEndpoint: "/knock-knock"
        approvalURL: "https://wallos.development.hhf.technology"
        notificationURL: "https://discord.com/api/webhooks/your-webhook-id"
        defaultPrivateClassSources: true
        expirationTime: 300
        ipStrategyDepth: 0
        secretKey: ""
        excludedIPs: []
        whitelistedIPs:
          - "127.0.0.1/32"
          - "192.168.1.0/24"
          - "10.0.0.0/8"
        redisEnabled: true
        redisAddress: "redis:6379"
        redisPassword: "${REDIS_PASSWORD:-changeme}"
        redisDB: 0
        redisKeyPrefix: "ipwhitelistshaper:"
```

## 4. Update Traefik Configuration

Update your static Traefik configuration to ensure the plugin has access to Redis:

```yaml
# In traefik_config.yml
api:
  insecure: true
  dashboard: true
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
    ipwhitelistshaper:
      moduleName: "github.com/hhftechnology/ipwhitelistshaper"
      version: "v1.0.0"
```

## 5. Configure Traefik Routers for Your Protected Service

Create a configuration file for your protected service in the `/rules` directory. For example, create `/rules/wallos.yml`:

```yaml
http:
  routers:
    # Main router for your protected service
    wallos-main:
      entryPoints:
        - websecure
      middlewares:
        - ipwhitelistshaper@file
      priority: 100
      rule: "Host(`wallos.development.hhf.technology`)"
      service: wallos-service
      tls:
        certResolver: letsencrypt
        
    # Router for the knock-knock endpoint
    wallos-knock:
      entryPoints:
        - websecure
      middlewares:
        - ipwhitelistshaper@file
      priority: 110
      rule: "Host(`wallos.development.hhf.technology`) && Path(`/knock-knock`)"
      service: wallos-service
      tls:
        certResolver: letsencrypt
        
    # Router for the approval endpoint
    wallos-approve:
      entryPoints:
        - websecure
      middlewares:
        - ipwhitelistshaper@file
      priority: 110
      rule: "Host(`wallos.development.hhf.technology`) && PathPrefix(`/approve`)"
      service: wallos-service
      tls:
        certResolver: letsencrypt
  
  services:
    wallos-service:
      loadBalancer:
        servers:
          - url: "http://your-service-name:port"
```

## 6. Create Redis Persistent Directory

Create the directory for Redis data persistence:

```bash
mkdir -p ./data/redis
chmod 777 ./data/redis
```

## 7. Apply the Changes

Restart your Docker Compose stack to apply all changes:

```bash
docker-compose down
docker-compose up -d
```

## 8. Verify Redis Connection

Check that Redis is running and that Traefik can connect to it:

```bash
# Check Redis is running
docker compose ps redis

# Check Redis logs
docker compose logs redis

# Check Traefik logs for any Redis connection errors
docker compose logs traefik
```

## 9. Test the Workflow

1. Try accessing your protected service (you should get a 403 Forbidden)
2. Visit the `/knock-knock` endpoint to request access
3. Check that you receive a notification with an approval link
4. Click the approval link to whitelist your IP
5. Try accessing the protected service again (you should now have access)

## Troubleshooting Redis Integration

If you encounter issues with the Redis integration:

1. **Redis Connection Errors**:
   - Check if Redis is running with `docker-compose ps redis`
   - Verify Redis password is correctly set
   - Ensure the Redis service is accessible from the Traefik container

2. **Plugin Configuration Issues**:
   - Make sure the Redis configuration is properly set in your middleware template
   - Verify that environment variables are correctly substituted
   - Check Traefik logs for any plugin initialization errors

3. **Plugin Not Loading**:
   - Ensure the go.mod file includes the Redis dependency
   - Verify that the Redis client package is properly imported
   - Check that vendored dependencies are included in your plugin repository

4. **Data Persistence Issues**:
   - Ensure Redis appendonly is enabled
   - Check permissions on the Redis data directory
   - Verify that Redis data is being saved by checking the data directory

By following these steps, you'll have a fully distributed IPWhitelistShaper solution with Redis backend integration that works reliably in your Pangolin infrastructure, even with multiple Traefik instances.