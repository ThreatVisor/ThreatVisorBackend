#!/bin/bash

SERVICE_NAME="multi-scanner-microservice"
SERVICE_DIR="/home/balakrishnansyon/multi-scanner-microservice"
PORT=4000

case "$1" in
    start)
        echo "🚀 Starting $SERVICE_NAME on port $PORT..."
        cd $SERVICE_DIR
        pm2 start ecosystem.config.cjs --env production
        ;;
    stop)
        echo "⏹️ Stopping $SERVICE_NAME..."
        pm2 stop $SERVICE_NAME
        ;;
    restart)
        echo "🔄 Restarting $SERVICE_NAME..."
        pm2 restart $SERVICE_NAME
        ;;
    status)
        echo "📊 Service Status:"
        pm2 status $SERVICE_NAME
        pm2 logs $SERVICE_NAME --lines 5
        ;;
    health)
        echo "🔍 Health Check on port $PORT:"
        curl -s http://localhost:$PORT/health | jq .
        ;;
    logs)
        echo "📋 Recent Logs:"
        pm2 logs $SERVICE_NAME --lines 20
        ;;
    reset)
        echo "🔄 Resetting $SERVICE_NAME..."
        pm2 delete $SERVICE_NAME 2>/dev/null || true
        pm2 start ecosystem.config.cjs --env production
        pm2 save
        ;;
    info)
        echo "📡 Service Information:"
        echo "   Port: $PORT"
        echo "   Health URL: http://localhost:$PORT/health"
        echo "   Scanners URL: http://localhost:$PORT/scanners"
        echo "   Public URL: http://your-azure-vm-ip:$PORT"
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|health|logs|reset|info}"
        exit 1
        ;;
esac
