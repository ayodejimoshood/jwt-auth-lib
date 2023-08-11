import express, { Express } from "express";
import cors from "cors";
import APP_CONFIG from "./_config";

const app: Express = express();

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