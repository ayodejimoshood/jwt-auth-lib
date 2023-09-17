// __tests__/server.test.ts

import { Express } from 'express';
import request from 'supertest';
import { app } from '../server'; // Adjust the path based on your folder structure

describe('Server API Endpoints', () => {
  let server: Express;

  beforeAll(() => {
    server = app;
  });

  afterAll(() => {
    // Clean up after tests if needed
  });

  it('should return "server is up" message', async () => {
    const response = await request(server).get('/');
    expect(response.status).toBe(200);
    expect(response.text).toContain('server is up');
  });

  // Add more test cases for your endpoints and functions

});

