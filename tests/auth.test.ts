// src/tests/validation.test.ts
import Joi from 'joi';
import { registerSchema, loginSchema } from '../src/validators/authValidators';

describe('Validation Schemas', () => {
  test('registerSchema should validate correct data', () => {
    const result = registerSchema.validate({ email: 'test@example.com', password: 'password123' });
    expect(result.error).toBeUndefined();
  });

  test('registerSchema should invalidate incorrect data', () => {
    const result = registerSchema.validate({ email: 'test', password: '123' });
    expect(result.error).not.toBeUndefined();
  });

  // Add more tests for loginSchema
});
