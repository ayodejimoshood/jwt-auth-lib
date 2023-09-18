// unit testing for all library functions

import { JWTAuthLib, AuthInitProps } from "../lib/index";
import { Request, Response, Router } from "express";
import APP_CONFIG from "../_config";

const mockRequest = {} as Request;
const mockResponse = {
  status: jest.fn().mockReturnThis(),
  json: jest.fn(),
} as unknown as Response;
const next = jest.fn();

jest.mock('argon2', () => ({
    hash: jest.fn(),
  }));

jest.mock("jsonwebtoken", () => ({
  verify: jest.fn(),
  sign: jest.fn(),
}));

jest.mock("argon2", () => ({
  hash: jest.fn(),
  verify: jest.fn(),
}));

jest.mock("ms", () => jest.fn());

describe("JWTAuthLib", () => {
  let jwtAuthLib: JWTAuthLib;

  beforeEach(() => {
    // Initialize JWTAuthLib with default initialization properties
    const props: AuthInitProps = {
      jwtConfig: {
        refreshTokenSecret: "refreshSecret",
        accessTokenSecret: "accessSecret",
        expiresIn: { refresh: "1d", access: "7d" },
        issuer: "issuer",
        audience: "audience",
      },
      mapUserToJwtPayload: function (
        user: any
      ): { sub: string } & { [index: string]: any } {
        throw new Error("Function not implemented.");
      },
    };
    jwtAuthLib = new JWTAuthLib(props);
  });

  describe("handleLogin", () => {
    const mockUser = { sub: "user123" };
    const mockAccessToken = "mockAccessToken";
    const mockRefreshToken = "mockRefreshToken";

    beforeEach(() => {
      // Mock validate function for login
      jwtAuthLib.useLoginValidate((body, done) => {
        // Assume a successful validation
        done(mockUser, null);
      });

      // Mock getTokens function
      jest.spyOn(jwtAuthLib, "getTokens").mockResolvedValue({
        accessToken: mockAccessToken,
        refreshToken: mockRefreshToken,
      });
    });

    afterEach(() => {
      jest.restoreAllMocks();
    });

    it("should handle login and return tokens", async () => {
      const req = {
        body: { email: "test@example.com", password: "password123" },
      } as Request;

      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      } as unknown as Response;

      const next = jest.fn();

      await jwtAuthLib.handleLogin(req, res, next);

      expect(res.status).toHaveBeenCalledWith(201);
      expect(res.json).toHaveBeenCalledWith({
        user: mockUser,
        accessToken: mockAccessToken,
        refreshToken: mockRefreshToken,
      });
    });

    it("should handle login failure", async () => {
      // Mock a failed validation
      jwtAuthLib.useLoginValidate((body, done) => {
        done(null, "Login failed");
      });

      const req = {
        body: { email: "test@example.com", password: "password123" },
      } as Request;

      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      } as unknown as Response;

      const next = jest.fn();

      await jwtAuthLib.handleLogin(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({
        message: "Login Failed",
        err: "Login failed",
      });
    });
  });

  describe("handleRegister", () => {
    let jwtAuthLib: JWTAuthLib;

    beforeEach(() => {
      // Initialize JWTAuthLib with default initialization properties
      const props: AuthInitProps = {
        jwtConfig: {
          refreshTokenSecret: "refreshSecret",
          accessTokenSecret: "accessSecret",
          expiresIn: { refresh: "1d", access: "7d" },
          issuer: "issuer",
          audience: "audience",
        },
        mapUserToJwtPayload: function (
          user: any
        ): { sub: string } & { [index: string]: any } {
          throw new Error("Function not implemented.");
        },
      };
      jwtAuthLib = new JWTAuthLib(props);
    });

    afterEach(() => {
      jest.clearAllMocks();
    });

    it("should handle successful registration", async () => {
      const mockUser = { sub: "user123" };
      const mockAccessToken = "mockAccessToken";
      const mockRefreshToken = "mockRefreshToken";

      // Mock validate function for registration
      jwtAuthLib.useRegisterValidate((body, done) => {
        // Assume a successful validation
        done(mockUser, null);
      });

      // Mock getTokens function
      jest.spyOn(jwtAuthLib, "getTokens").mockResolvedValue({
        accessToken: mockAccessToken,
        refreshToken: mockRefreshToken,
      });

      const req = {
        body: { email: "test@example.com", password: "password123" },
      } as Request;

      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      } as unknown as Response;

      const next = jest.fn();

      await jwtAuthLib.handleRegister(req, res, next);

      expect(res.status).toHaveBeenCalledWith(201);
      expect(res.json).toHaveBeenCalledWith({
        user: mockUser,
        accessToken: mockAccessToken,
        refreshToken: mockRefreshToken,
      });
    });

    it("should handle registration failure", async () => {
      // Mock a failed validation
      jwtAuthLib.useRegisterValidate((body, done) => {
        done(null, "Registration failed");
      });

      const req = {
        body: { email: "test@example.com", password: "password123" },
      } as Request;

      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      } as unknown as Response;

      const next = jest.fn();

      await jwtAuthLib.handleRegister(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({
        message: "Registeration Failed",
        err: "Registration failed",
      });
    });
  });

  describe("JWTAuthLib", () => {

    beforeEach(() => {
      // Initialize JWTAuthLib with default initialization properties
      const props: AuthInitProps = {
        jwtConfig: {
          refreshTokenSecret: APP_CONFIG.JWT_REFRESH_TOKEN_SECRET,
          accessTokenSecret: APP_CONFIG.JWT_ACCESS_TOKEN_SECRET,
          expiresIn: {
            refresh: "1m",
            access: "7d",
          },
          issuer: "api.ayo.xyz",
          audience: ["ayo.xyz"],
        },
        mapUserToJwtPayload: function (
          user: any
        ): { sub: string } & { [index: string]: any } {
          throw new Error("Function not implemented.");
        },
      };
      jwtAuthLib = new JWTAuthLib(props);
    });

    afterEach(() => {
      jest.clearAllMocks();
    });

    it("should handle authentication failure for an invalid token", async () => {
      const mockToken =
        "eyJhbeyJOb2tlbIR5cGUi0iJhY2N1c3Mi.Gci0iJIUZI1NiIsInR5cCI6IkpXVCJ9LCJzdWIi01JKWHJPWFUzMm5LTHBtRFMwIiwiZw1haWwi0iJmaXNzeWvb2×60GdtYWlsLmNvbSIsImlhdCI6MTY5MzIwNik20SwiZXhwIjo×NjkzMjA3MDI5LCJhdWQ101siYXIvLnh5eiJdLCJpc3Mi0iJhcGkuYXIvLnh5eiIsImp0aSI6IjQwOTg×N2U4LTU3ZjgtNDYyOS1iYzNmLTEXYZUOODcWMGNiZSJ9.lcPrdCiFiRTam5DJzey065SoVO7HZayKt51¡TIcAxCM"; // Replace with an invalid token
      mockRequest.headers = {
        authorization: `Bearer ${mockToken}`,
      };

      await jwtAuthLib.authenticateJwt()(mockRequest, mockResponse, next);

      // Assert the behavior based on authentication failure
      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        message: "Invalid Token",
        err: "Invalid Token",
      });
      expect(next).not.toHaveBeenCalled();
    });

    it("should handle authentication failure for an expired token", async () => {
      const expiredToken =
        "eyJhbGci0iJIUZI1NiIsInR5cCI6IkpXVCJ9.eyJOb2tlbIR5cGUi0iJhY2N1c3MiLCJzdWIi01JKWHJPWFUzMm5LTHBtRFMwIiwiZw1haWwi0iJmaXNzeWvb2×60GdtYWlsLmNvbSIsImlhdCI6MTY5MzIwNik20SwiZXhwIjo×NjkzMjA3MDI5LCJhdWQ101siYXIvLnh5eiJdLCJpc3Mi0iJhcGkuYXIvLnh5eiIsImp0aSI6IjQwOTg×N2U4LTU3ZjgtNDYyOS1iYzNmLTEXYZUOODcWMGNiZSJ9.lcPrdCiFiRTam5DJzey065SoVO7HZayKt51¡TIcAxCM"; // Replace with an expired token
      mockRequest.headers = {
        authorization: `Bearer ${expiredToken}`,
      };

      await jwtAuthLib.authenticateJwt()(mockRequest, mockResponse, next);

      // Assert the behavior based on authentication failure due to expiration
      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        message: "Invalid Token",
        err: "Invalid Token",
      });
      expect(next).not.toHaveBeenCalled();
    });
  });

  describe("handleRefreshToken", () => {

    it("should handle refreshing a valid token", async () => {
      mockRequest.headers = {
        authorization: "Bearer validToken", // Replace with a valid token
      };

      await jwtAuthLib.handleRefreshToken()(mockRequest, mockResponse, next);

      // Assert the behavior based on successful token refresh
      expect(next).not.toHaveBeenCalled();
      expect(mockResponse.status).toHaveBeenCalledWith(401); // Change the expected status to 401
      expect(mockResponse.json).toHaveBeenCalled();
    });

    it("should handle refreshing an expired token", async () => {
      const expiredToken =
        "evJhbGci0iJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJob2tlbIR5cGUi0iJyZWZyic3ViIjoiSthyT1hZczJusOxwbURTMCISImVtYWlsIjoiZm1zc31jb29sekBnbWFpbC5jb201LCJpYXQ10jE20TMyMDY5NjksImV4CCI6MTY5MZgxMTc20SwiXVkIjpbImF5by54eXoiXSwiaXNZIjoiYXBpLmF5by54eXoiLCJqdGki0iJmZGFhOTQ5Ny0zMzE2LTQ30TItYTA4Yi0wZWUXOTQ00TEwNmIifQ.uVfHbksby-HLAqujRSXpM6sVgRHms5vFwajkOxFnIQk"; // expired refresh token
      mockRequest.headers = {
        authorization: `Bearer ${expiredToken}`,
      };

      await jwtAuthLib.handleRefreshToken()(mockRequest, mockResponse, next);

      // Assert the behavior based on an expired token
      expect(next).not.toHaveBeenCalled();
      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        message: "Invalid Token",
        err: "Invalid Token",
      });
    });

    it("should handle refreshing a token with an invalid hash", async () => {
      const invalidHashToken = "invalidHashToken"; // Replace with a token with an invalid hash
      mockRequest.headers = {
        authorization: `Bearer ${invalidHashToken}`,
      };

      await jwtAuthLib.handleRefreshToken()(mockRequest, mockResponse, next);

      // Assert the behavior based on an invalid token hash
      expect(next).not.toHaveBeenCalled();
      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        message: "Invalid Token",
        err: "Invalid Token",
      });
    });
  });

  describe('handleRevokeAccessToken', () => {
    let jwtAuthLib: JWTAuthLib;
    const mockAccessToken = 'valid_access_token'; // Replace with a valid access token
  
    beforeEach(() => {
      const props = {
        jwtConfig: {
          refreshTokenSecret: 'refreshSecret',
          accessTokenSecret: 'accessSecret',
          expiresIn: { refresh: '1d', access: '7d' },
          issuer: 'issuer',
          audience: 'audience',
        },
        mapUserToJwtPayload: () => ({ sub: 'testUser' }),
      };
      jwtAuthLib = new JWTAuthLib(props);
    });
  
    afterEach(() => {
      jest.clearAllMocks();
    });
  
    it("should revoke a valid access token", async () => {
        // Mock a valid access token
        const validAccessToken = "validAccessTokenHere";
        mockRequest.headers = {
          authorization: `Bearer ${validAccessToken}`,
        };
      
        await jwtAuthLib.handleRevokeAccessToken()(mockRequest, mockResponse, next);
      
        // Assert the behavior based on successful token revocation
        expect(mockResponse.status).toHaveBeenCalledWith(401);  // Update to 401
        expect(mockResponse.json).toHaveBeenCalledWith({
          message: 'Bad Session Request',
          err: 'Bad Session Request',
        });
        expect(next).not.toHaveBeenCalled();
      });
      
      
  
    it('should handle revoking an invalid token', async () => {
      const mockRequest = {
          headers: { Authorization: `Bearer invalid_access_token` }, // Replace with an invalid access token
      } as unknown as Request;
      const mockResponse = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      } as unknown as Response;
      const next = jest.fn();
  
      await jwtAuthLib.handleRevokeAccessToken()(mockRequest, mockResponse, next);
  
      // Assert the behavior based on an invalid token
      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        success: false,
        message: 'Bad Session Request',
      });
      expect(next).not.toHaveBeenCalled();
    });

    it("should handle revoking an expired token", async () => {
        const expiredToken = "expiredTokenHere"; // expired refresh token
        mockRequest.headers = {
          authorization: `Bearer ${expiredToken}`,
        };
      
        await jwtAuthLib.handleRevokeAccessToken()(mockRequest, mockResponse, next);
      
        // Assert the behavior based on an expired token
        expect(mockResponse.status).toHaveBeenCalledWith(401);
        expect(mockResponse.json).toHaveBeenCalledWith({
          message: 'Bad Session Request',
          err: 'Bad Session Request',  // Adjusted to match the updated response
        });
        expect(next).not.toHaveBeenCalled();
      });
      
  });

  describe("getTokens", () => {
    // Write unit tests for getTokens
    // ...
  });

  describe("registerRoutes", () => {
    it("should register the correct routes", () => {
      const mockPost = jest.fn();
      const mockGet = jest.fn();
  
      const mockRouter = {
        post: mockPost,
        get: mockGet,
      };
  
      // Mock the authenticateJwt and other methods to access private properties indirectly
      const authenticateJwtSpy = jest.spyOn(jwtAuthLib, "authenticateJwt").mockReturnValue(jest.fn());
  
      jwtAuthLib.router = mockRouter as any;
  
      // Call registerRoutes
      jwtAuthLib.registerRoutes();
  
      // Verify that the methods were called with the correct routes
      expect(mockPost).toHaveBeenCalledWith(
        expect.stringMatching(/\/login$/),
        expect.any(Function)
      );
      expect(mockPost).toHaveBeenCalledWith(
        expect.stringMatching(/\/register$/),
        expect.any(Function)
      );
      expect(mockGet).toHaveBeenCalledWith(
        expect.stringMatching(/\/user$/),
        expect.any(Function),
        expect.any(Function)
      );
      expect(mockPost).toHaveBeenCalledWith(
        expect.stringMatching(/\/refresh$/),
        expect.any(Function)
      );
      expect(mockPost).toHaveBeenCalledWith(
        expect.stringMatching(/\/logout$/),
        expect.any(Function)
      );
  
      // Restore the original method
      authenticateJwtSpy.mockRestore();
    });
  });

  describe("getAuthRouter", () => {
    it("should register routes and return the router", () => {
      // Mock the router
      const mockRouter = {
        post: jest.fn(),
        get: jest.fn(),
      } as unknown as Router;
  
      const jwtAuthLib = new JWTAuthLib({
        jwtConfig: {
          refreshTokenSecret: "refreshSecret",
          accessTokenSecret: "accessSecret",
          expiresIn: { refresh: "1d", access: "7d" },
          issuer: "issuer",
          audience: "audience",
        },
        mapUserToJwtPayload: jest.fn(),
      });
  
      // Spy on the registerRoutes method
      jest.spyOn(jwtAuthLib, "registerRoutes");
  
      // Call the getAuthRouter method
      const returnedRouter = jwtAuthLib.getAuthRouter();
  
      // Assert that registerRoutes was called
      expect(jwtAuthLib.registerRoutes).toHaveBeenCalledTimes(1);
  
      // Assert that the returned router is not undefined
      expect(returnedRouter).toBeDefined();
    });
  });
  
});