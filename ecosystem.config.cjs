module.exports = {
  apps: [
    {
      name: 'zktls-attestator',
      script: 'server.js',
      instances: 1,
      exec_mode: 'fork',
      env: { NODE_ENV: 'production' },
      max_memory_restart: '1G',
    },
  ],
};
