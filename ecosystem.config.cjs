module.exports = {
  apps: [{
    name: "threatvisor-backend",
    script: "./index.mjs",
    instances: 1,
    autorestart: true,
    watch: false,
    max_memory_restart: '1G',
    env: {
      NODE_ENV: "production",
      PORT: 4000
    }
  }]
};
