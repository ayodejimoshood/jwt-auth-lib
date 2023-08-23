import express, { Express } from "express";
import cors from "cors";
import APP_CONFIG from "./_config";
import { JWTAuthLib, AuthInitProps } from "./lib";
import { loadAllDb, userDb } from "./db";

type User = {
  _id: string;
  email: string;
};

type LoginPayload = {
  email: string;
  password: string;
};

type RegisterPayload = {
  email: string;
  password: string;
};

const app: Express = express();

const AuthStrategy = new JWTAuthLib();

AuthStrategy.init({
  // redisConfig: {
  //   host: "<redis-host-url>", // redis host url placeholder
  //   port: 6379,
  //   username: "<redis-username>",
  //   password: "<redis-password>",
  // },
  // authRoute: "<custom-auth-route>", // placeholder
  redisUrl: APP_CONFIG.REDIS_URL,

  mapUserToJwtPayload: (user: User) => ({ sub: user._id, email: user?.email }),
  jwtConfig: {
    accessTokenSecret: APP_CONFIG.JWT_ACCESS_TOKEN_SECRET,
    refreshTokenSecret: APP_CONFIG.JWT_REFRESH_TOKEN_SECRET,
    expiresIn: {
      access: "1m",
      refresh: "7d",
    },
    issuer: "api.ayo.xyz",
    audience: ["ayo.xyz"],
  },
});

AuthStrategy.useLoginValidate((loginInfo: LoginPayload, done) => {
  userDb.findOne({ email: loginInfo.email }, (err, existingUser) => {
    if (err) return done(null, err);
    if (!existingUser) return done(null, "Password/Email Mismatch");
    if (existingUser?.password !== loginInfo?.password) {
      return done(null, "Invalid Credentials");
    }
    done(existingUser, null);
  });
});

AuthStrategy.useRegisterValidate((newUser: RegisterPayload, done) => {
  userDb.findOne({ email: newUser?.email }, (err, existingUser) => {
    if (err) {
      return done(null, err);
    }

    // check if user already exist in the Db
    if (existingUser) {
      return done(null, "User Already Exists");
    }

    // developer handling request payload validation
    if (!newUser.email || !newUser.password) {
      return done(null, "Please ensure email or password is provided");
    }

    // create user
    userDb.insert(newUser, (err, doc) => {
      if (err) {
        return done(null, err);
      }
      done(doc, null);
    });
  });
});

AuthStrategy.useJwtValidate(({ sub }: { sub: string; email: string }, done) => {
  userDb.findOne({ _id: sub }, (err, doc) => {
    if (err) {
      return done(null, "Please Login");
    }
    done(doc, null);
  });
});

app.use(express.json());
app.use(cors());

// Mount Optional Auth Router Middleware
app.use(AuthStrategy.getAuthRouter()); // base route can be configured in jwt-auth-lib initialization

// Protect a route using authenticateJwt middleware
app.get("/", (req, res) => {
  // The authenticated user's information can be accessed using req.user
  res.send("server is up");
});

// Usage of Handlers

// Protect a route using authenticateJwt middleware - Validates Access Token
// app.get("/auth/user", AuthStrategy.authenticateJwt(), (req, res) => {
//   // The authenticated user's information can be accessed using req.user
//   res.json({ user: req.user });
// });

// // Handle refresh token route
// app.post("/auth/refresh", AuthStrategy.handleRefreshToken());

// // Handle Logout Route
// app.post("/auth/logout", AuthStrategy.handleRevokeAccessToken());

// // Handle Register Route
// app.post("/auth/register", AuthStrategy.handleRegister);

// // Handle Login Route
// app.post("/auth/login", AuthStrategy.handleLogin);

// Handle Get User Route
// app.get("/auth/user", AuthStrategy.handleGetUser);

app.listen(APP_CONFIG.PORT, () => {
  console.log(
    `[⚡️ server]: Server is running at http://localhost:${APP_CONFIG.PORT}`
  );
  console.log("Loading Database...");
  loadAllDb();
});
