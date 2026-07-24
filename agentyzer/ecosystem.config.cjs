const fs = require("node:fs");
const path = require("node:path");

function loadDotEnv(filePath) {
  if (!fs.existsSync(filePath)) {
    return {};
  }

  const env = {};
  for (const line of fs.readFileSync(filePath, "utf8").split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }

    const separatorIndex = trimmed.indexOf("=");
    if (separatorIndex === -1) {
      continue;
    }

    const key = trimmed.slice(0, separatorIndex).trim();
    let value = trimmed.slice(separatorIndex + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    env[key] = value;
  }

  return env;
}

const dotEnv = loadDotEnv(path.join(__dirname, ".env"));
const port = process.env.PORT || dotEnv.PORT || 8000;

module.exports = {
  apps: [
    {
      name: "agentyzer-local",
      cwd: __dirname,
      script: "uv",
      args: [
        "run",
        "uvicorn",
        "src.main:app",
        "--host",
        "0.0.0.0",
        "--port",
        String(port),
        "--reload",
      ],
      interpreter: "none",
      exec_mode: "fork",
      watch: false,
      autorestart: true,
      env: {
        ...dotEnv,
        PYTHONUNBUFFERED: "1",
        AGENTYZER_CONFIG_DIR: "config",
        AGENTYZER_LOG_LEVEL: "INFO",
        PORT: String(port),
      },
    },
  ],
};
