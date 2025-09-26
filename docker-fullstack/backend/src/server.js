const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const redis = require('redis');

const app = express();
const PORT = process.env.PORT || 5000;

// 미들웨어
app.use(cors());
app.use(express.json());

// 데이터베이스 연결
const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

// Redis 연결
const redisClient = redis.createClient({
  url: process.env.REDIS_URL
});
redisClient.connect();

// 라우트
app.get('/api/health', async (req, res) => {
  try {
    const dbResult = await pool.query('SELECT NOW()');
    const redisResult = await redisClient.ping();
    
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      version: process.env.APP_VERSION || '1.0.0',
      database: dbResult.rows[0].now,
      cache: redisResult === 'PONG' ? 'connected' : 'disconnected'
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/users', async (req, res) => {
  try {
    // Redis 캐시 확인
    const cached = await redisClient.get('users');
    if (cached) {
      return res.json(JSON.parse(cached));
    }

    // 데이터베이스에서 조회
    const result = await pool.query('SELECT * FROM users ORDER BY id');
    
    // Redis에 캐시 저장 (5분)
    await redisClient.setEx('users', 300, JSON.stringify(result.rows));
    
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Prometheus 메트릭 수집
let httpRequestsTotal = 0;
let httpRequestDuration = [];
let activeConnections = 0;
let errorCount = 0;

// 메트릭 수집 미들웨어
app.use((req, res, next) => {
  const start = Date.now();
  httpRequestsTotal++;
  activeConnections++;
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    httpRequestDuration.push(duration);
    activeConnections--;
    
    if (res.statusCode >= 400) {
      errorCount++;
    }
  });
  
  next();
});

// Prometheus 메트릭 엔드포인트
app.get('/metrics', (req, res) => {
  const avgDuration = httpRequestDuration.length > 0 
    ? httpRequestDuration.reduce((a, b) => a + b) / httpRequestDuration.length 
    : 0;
    
  res.set('Content-Type', 'text/plain');
  res.send(`# HELP http_requests_total Total HTTP requests
# TYPE http_requests_total counter
http_requests_total ${httpRequestsTotal}

# HELP http_request_duration_ms Average HTTP request duration in milliseconds
# TYPE http_request_duration_ms gauge
http_request_duration_ms ${avgDuration}

# HELP http_active_connections Current active connections
# TYPE http_active_connections gauge
http_active_connections ${activeConnections}

# HELP http_errors_total Total HTTP errors (4xx, 5xx)
# TYPE http_errors_total counter
http_errors_total ${errorCount}

# HELP nodejs_memory_usage_bytes Node.js memory usage
# TYPE nodejs_memory_usage_bytes gauge
nodejs_memory_usage_bytes{type="rss"} ${process.memoryUsage().rss}
nodejs_memory_usage_bytes{type="heapTotal"} ${process.memoryUsage().heapTotal}
nodejs_memory_usage_bytes{type="heapUsed"} ${process.memoryUsage().heapUsed}
`);
});

app.listen(PORT, () => {
  console.log(`Backend server running on port ${PORT}`);
});

