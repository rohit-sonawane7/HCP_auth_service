// src/middlewares/validationMiddleware.ts
import { Request, Response, NextFunction } from 'express';
import Joi from 'joi';

export const validate = (schema: Joi.ObjectSchema) => (req: Request, res: Response, next: NextFunction): void => {
    const { error } = schema.validate(req.body, { abortEarly: false });
    if (error) {
        res.status(400).json({ errors: error.details.map(detail => detail.message) });
    } else {
        next();
    }
};
