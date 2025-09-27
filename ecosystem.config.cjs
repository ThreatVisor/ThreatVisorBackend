module.exports = {
  apps: [{
    name: 'multi-scanner-microservice',
    script: './index.mjs',
    cwd: '/home/balakrishnansyon/multi-scanner-microservice',
    instances: 1,
    exec_mode: 'fork',
    autorestart: true,
    watch: false,
    max_memory_restart: '2G',
    env: {
      NODE_ENV: 'production',
      PORT: 4000,
      OPENAI_API_KEY: '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',
      OPENAI_MODEL: 'gpt-5'
    },
    env_production: {
      NODE_ENV: 'production',
      PORT: 4000
    },
    log_file: './logs/combined.log',
    out_file: './logs/out.log',
    error_file: './logs/error.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    merge_logs: true,
    time: true,
    min_uptime: '10s',
    max_restarts: 5,
    restart_delay: 2000
  }]
};
