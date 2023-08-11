import dotenv from "dotenv";

dotenv.config();

const APP_CONFIG = {
  PORT: process.env.PORT || 9000,
};

export default APP_CONFIG;