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
    redisUrl?: string;
    redisConfig?: {host:string, username: string, password:string, port: number};
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
    private validateFns: Record<string, ValidateFn> = {};
    public mapUserToJwtPayload = defaultInitProps.mapUserToJwtPayload;
    private tokenRepository: Repository | undefined;

    constructor(props: AuthInitProps = defaultInitProps) {
        this.init(props,!!props.redisUrl||!!props.redisConfig);
    }
    
    init({ jwtConfig, redisUrl, redisConfig, authRoute, mapUserToJwtPayload }: AuthInitProps, instantiateRedis:boolean=true) {
        this.jwtConfig = jwtConfig;
        this.authRoute = authRoute || this.authRoute;
        this.mapUserToJwtPayload = mapUserToJwtPayload;
        this.router = Router();
        
        // console.log("redis://default:laLBzbtYOzTZbyU9CEMNAcoVAV8d5uE0@redis-14649.c85.us-east-1-2.ec2.cloud.redislabs.com:14649")
        if(instantiateRedis) {
          const config = redisConfig?{
            socket: {
              host: redisConfig.host,
              port: redisConfig.port
            }, password: redisConfig.password,
            username: redisConfig.username}:{url:redisUrl
          }
          this.redis = createClient(config);
          this.tokenRepository = new Repository(tokenSchema, this.redis);
          this.registerRedisEvents();
          this.redis.connect();
        }
    }
    
    registerRedisEvents() {
        if (this.redis) {
            this.redis?.on("error", (err) => { 
                console.log("[Redis Auth Client]:", err)
            }
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

    useJwtValidate(
        validateFn: (jwtPayload: any, done: (user: any, err: any) => void) => void
    ){
        this.validateFns["jwt"] = validateFn;
    }
    useLoginValidate(validateFn: ValidateFn) {
        this.validateFns[ALLOWED_ROUTES.LOGIN] = validateFn;
    }
    
    useRegisterValidate(validateFn: ValidateFn) {
        this.validateFns[ALLOWED_ROUTES.REGISTER] = validateFn;
    }
}

export default JWTAuthLib;