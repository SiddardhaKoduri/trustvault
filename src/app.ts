import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import authRoutes from './routes/auth.routes.js';

export const app = express();

// 1. Security Headers (Defends against XSS, Clickjacking, MIME-sniffing)
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'blob:'],
      },
    },
    crossOriginEmbedderPolicy: false,
  })
);

// 2. CORS configuration for frontend credentials
app.use(
  cors({
    origin: process.env.CLIENT_URL || 'http://localhost:3000',
    credentials: true,
  })
);

// 3. Request parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// 4. Healthcheck & Security Telemetry
app.get('/api/health', (req: Request, res: Response) => {
  res.status(200).json({
    status: 'HEALTHY',
    service: 'TrustVault Zero-Trust Security Engine',
    timestamp: new Date().toISOString(),
  });
});

// 5. Mount API Routes
app.use('/api/auth', authRoutes);

// 6. 404 Handler
app.use((req: Request, res: Response) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// 7. Centralized Error Handler (Masks internal stack traces to mitigate Threat I-03)
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  console.error('Unhandled Server Exception:', err);
  const statusCode = err.statusCode || 500;
  const message =
    process.env.NODE_ENV === 'production'
      ? 'An internal security exception occurred. Request logged.'
      : err.message || 'Internal server error';

  res.status(statusCode).json({
    error: message,
    timestamp: new Date().toISOString(),
  });
});
