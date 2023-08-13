import express, { Express } from "express";
import cors from "cors";
import APP_CONFIG from "./_config";
import { JWTAuthLib } from "./lib";

type User = {
    _id: string;
    email: string;
};
console.log(APP_CONFIG)

const app: Express = express();

const AuthStrategy = new JWTAuthLib();

AuthStrategy.init({
    redisUrl: APP_CONFIG.REDIS_URL,
    // redisConfig: {host:"redis-14649.c85.us-east-1-2.ec2.cloud.redislabs.com", port: 14649, username:"default", password: 'laLBzbtYOzTZbyU9CEMNAcoVAV8d5uE0'},
    mapUserToJwtPayload: (user: User) => ({ sub: user._id, email: user?.email }),
    jwtConfig: {
      accessTokenSecret: APP_CONFIG.JWT_ACCESS_TOKEN_SECRET,
      refreshTokenSecret: APP_CONFIG.JWT_REFRESH_TOKEN_SECRET,
      expiresIn: {
        access: "1d",
        refresh: "7d",
      },
      issuer: "api.ayo.xyz",
      audience: ["ayo.xyz"],
    },
});

app.use(express.json());
app.use(cors());

// Protect a route using authenticateJwt middleware
app.get("/", (req, res) => {
    // The authenticated user's information can be accessed using req.user
    res.send("server is up");
});
  

app.listen(APP_CONFIG.PORT, () => {
    console.log(
      `[⚡️ server]: Server is running at http://localhost:${APP_CONFIG.PORT}`
    );
});