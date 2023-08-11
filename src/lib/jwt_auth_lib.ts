import { Router, Request, Response, NextFunction } from "express";
import { createClient, RedisClientType } from "redis";
import { Schema, Repository } from "redis-om";

enum TokenType {
    REFRESH = "refresh",
    ACCESS = "access",
}
  
type JWT_CONFIG = {
    refreshTokenSecret: string;
    accessTokenSecret: string;
    expiresIn: {
      refresh: string;
      access: string;
    };
    issuer: string;
    audience: string | string[];
};

export type TokenSchema = {
    sub: string;
    hashedToken: string;
    type: TokenType;
    expires_in: string;
  };

const tokenSchema = new Schema(
    "tokens",
    {
      sub: { type: "string" },
      hashedToken: { type: "string" },
      type: { type: "string" },
      expires_in: { type: "string" },
    },
    {
      dataStructure: "HASH",
    }
);

export type AuthInitProps = {
    jwtConfig: JWT_CONFIG;
    redisUrl: string;
    authRoute?: string;
    mapUserToJwtPayload: (
      user: any
    ) => { sub: string } & { [index: string]: any };
};

// possible authentication route
enum ALLOWED_ROUTES {
    LOGIN = "login",
    REGISTER = "register",
    LOGOUT = "logout",
    USER = "user",
    REFRESH = "refresh",
}

type ValidateFn = (body: any, done: (user: any, err: any) => void) => void;

const defaultInitProps: AuthInitProps = {
    redisUrl: "",
    authRoute: "/auth",
    mapUserToJwtPayload: () => ({
      sub: "",
    }),
    jwtConfig: {
      accessTokenSecret: "",
      refreshTokenSecret: "",
      expiresIn: {
        refresh: "1d",
        access: "7d",
      },
      issuer: "",
      audience: "",
    },
};

class JWTAuthLib {
    private jwtConfig: JWT_CONFIG = defaultInitProps.jwtConfig;
    private redis: RedisClientType | undefined;
    private authRoute?: string = defaultInitProps.authRoute;
    public router: Router = Router();
    public mapUserToJwtPayload = defaultInitProps.mapUserToJwtPayload;
    private tokenRepository: Repository | undefined;

    constructor(props: AuthInitProps = defaultInitProps) {
        this.init(props);
    }
    
    init({ jwtConfig, redisUrl, authRoute, mapUserToJwtPayload }: AuthInitProps) {
        this.jwtConfig = jwtConfig;
        this.authRoute = authRoute || this.authRoute;
        this.mapUserToJwtPayload = mapUserToJwtPayload;
        this.router = Router();
        this.redis = createClient({
          url: redisUrl,
        });
        this.tokenRepository = new Repository(tokenSchema, this.redis);
        this.registerRedisEvents();
        this.redis.connect();
    }
    
    registerRedisEvents() {
        if (this.redis) {
          this.redis?.on("error", (err) =>
            console.log("[Redis Auth Client]:", err)
          );
          this.redis.on("connect", () =>
            console.log("[Redis Auth Client]:connected to redis successfully ")
          );
          this.redis.on("end", () =>
            console.log("[Redis Auth Client]:disconnected from redis ")
          );
          this.redis.on("reconnecting", () =>
            console.log("[Redis Auth Client]:reconnecting to redis ")
          );
        }
    }
}

export default JWTAuthLib;