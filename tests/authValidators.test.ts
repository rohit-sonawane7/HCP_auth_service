// src/tests/authValidators.test.ts
import { registerSchema, loginSchema } from '../src/validators/authValidators';

describe('Validation Schemas', () => {
    test('registerSchema should validate correct data', () => {
        const result = registerSchema.validate({
            email: 'test@example.com',
            password: 'password123',
        });
        expect(result.error).toBeUndefined();
    });

    test('registerSchema should invalidate incorrect data', () => {
        const result = registerSchema.validate({
            email: 'invalid-email',
            password: 'short',
        });
        expect(result.error).toBeDefined();
        expect(result.error?.details[0].message).toBe('Invalid email address');
        expect(result.error?.details[1].message).toBe('Password must be at least 6 characters long');
    });

    test('loginSchema should validate correct data', () => {
        const result = loginSchema.validate({
            email: 'test@example.com',
            password: 'password123',
        });
        expect(result.error).toBeUndefined();
    });

    test('loginSchema should invalidate incorrect data', () => {
        const result = loginSchema.validate({
            email: 'invalid-email',
            password: '',
        });
        expect(result.error).toBeDefined();
        expect(result.error?.details[0].message).toBe('Invalid email address');
        expect(result.error?.details[1].message).toBe('Password is required');
    });
});
