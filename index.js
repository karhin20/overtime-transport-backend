const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();

// CORS configuration
const corsOptions = {
  origin: process.env.FRONTEND_URL ,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  optionsSuccessStatus: 200
};

// Apply CORS with options
app.use(cors(corsOptions));

// Middleware
app.use(express.json());

// Rate limiting
{/*const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);*/}

// Supabase client with service role
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (error) {
    res.status(400).json({ error: 'Invalid token' });
  }
};

// Admin signup - requires secret code
app.post('/api/admin/signup', [
  body('email').isEmail(),
  body('password').isLength({ min: 6 }),
  body('secretCode').notEmpty(),
  body('name').notEmpty(),
  body('staffId').notEmpty(),
  body('grade').notEmpty(),
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password, secretCode, name, staffId, grade } = req.body;

    // Verify secret code
    if (secretCode !== process.env.ADMIN_SECRET_CODE) {
      return res.status(403).json({ error: 'Invalid secret code' });
    }

    // Check if admin already exists
    const { data: existingAdmin } = await supabase
      .from('admins')
      .select('email')
      .eq('email', email)
      .single();

    if (existingAdmin) {
      return res.status(400).json({ error: 'Admin already exists' });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create admin in database
    const { data: admin, error } = await supabase
      .from('admins')
      .insert([
        { 
          email, 
          password: hashedPassword, 
          name, 
          staff_id: staffId,
          grade 
        }
      ])
      .select()
      .single();

    if (error) {
      console.error('Supabase error:', error);
      throw error;
    }

    // Generate JWT token
    const token = jwt.sign({ id: admin.id }, process.env.JWT_SECRET);
    res.json({
      token,
      user: {
        name: admin.name,
        staffId: admin.staff_id,
        grade: admin.grade
      }
    });

  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Admin signin
app.post('/api/admin/signin', [
  body('email').isEmail(),
  body('password').notEmpty(),
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    // Get admin from database
    const { data: admin, error } = await supabase
      .from('admins')
      .select('*')
      .eq('email', email)
      .single();

    if (error || !admin) {
      return res.status(400).json({ error: 'Admin not found' });
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, admin.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid password' });
    }

    // Generate JWT token
    const token = jwt.sign({ id: admin.id }, process.env.JWT_SECRET);
    res.json({
      token,
      user: {
        name: admin.name,
        staffId: admin.staff_id,
        grade: admin.grade
      }
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Protected routes for worker management
app.post('/api/workers', authenticateToken, [
  body('name').notEmpty(),
  body('staffId').notEmpty(),
  body('grade').notEmpty(),
  body('defaultArea').notEmpty(),
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { data, error } = await supabase
      .from('workers')
      .insert([{
        name: req.body.name,
        staff_id: req.body.staffId,
        grade: req.body.grade,
        default_area: req.body.defaultArea,
        transport_required: req.body.transportRequired
      }])
      .select();

    if (error) throw error;
    res.json(data[0]);

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get all workers
app.get('/api/workers', authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('workers')
      .select('*');

    if (error) throw error;
    res.json(data);

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get worker's overtime entry
app.post('/api/overtime', authenticateToken, async (req, res) => {
  try {
    const { worker_id, date } = req.body;

    // Check for existing entry
    const { data: existingEntry } = await supabase
      .from('overtime_entries')
      .select('id')
      .eq('worker_id', worker_id)
      .eq('date', date)
      .maybeSingle();

    if (existingEntry) {
      return res.status(409).json({ 
        error: 'An entry already exists for this worker on the selected date' 
      });
    }

    // First get the worker to check their default area
    const { data: worker, error: workerError } = await supabase
      .from('workers')
      .select('*')
      .eq('id', worker_id)
      .single();

    if (workerError) throw workerError;

    // Get the rate for the worker's default area
    const { data: areaData, error: areaError } = await supabase
      .from('areas')
      .select('rate')
      .eq('default_area', worker.default_area)
      .single();

    if (areaError) throw areaError;

    // Set transportation_cost when transportation is true
    const transportation_cost = req.body.transportation ? areaData.rate : null;

    const { data, error } = await supabase
      .from('overtime_entries')
      .insert([{
        worker_id: worker_id,
        date: date,
        entry_time: req.body.entry_time,
        exit_time: req.body.exit_time,
        category: req.body.category,
        category_a_hours: req.body.category_a_hours,
        category_c_hours: req.body.category_c_hours,
        transportation: req.body.transportation,
        transportation_cost: transportation_cost
      }])
      .select(`
        *,
        workers (
          name,
          staff_id,
          grade,
          default_area
        )
      `);

    if (error) {
      console.error('Insert error:', error);
      throw error;
    }

    res.json(data[0]);

  } catch (error) {
    console.error('Error creating overtime entry:', error);
    res.status(500).json({ error: 'Failed to create overtime entry. DUPLICATE Entry or Network issues' });
  }
});

// Get overtime entries for a worker
app.get('/api/overtime/:workerId', authenticateToken, async (req, res) => {
  try {
    const { workerId } = req.params;
    const { month, year } = req.query;

    const formattedMonth = month.toString().padStart(2, '0');
    const startDate = `${year}-${formattedMonth}-01`;
    const endDate = new Date(year, month, 0).toISOString().split('T')[0];

    const { data: entries, error } = await supabase
      .from('overtime_entries')
      .select(`
        *,
        workers (
          name,
          staff_id,
          grade,
          default_area
        )
      `)
      .eq('worker_id', workerId)
      .gte('date', startDate)
      .lte('date', endDate)
      .order('date', { ascending: true });

    if (error) throw error;

    // Ensure transportation_cost is always a number
    const processedData = entries.map(entry => ({
      ...entry,
      transportation_cost: entry.transportation ? 
        (entry.transportation_cost || parseFloat(entry.workers.default_area) || 0) : 
        0
    }));

    res.json(processedData);

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get monthly summary
app.get('/api/summary/monthly', authenticateToken, async (req, res) => {
  try {
    const { month, year } = req.query;
    
    const formattedMonth = month.toString().padStart(2, '0');
    const startDate = `${year}-${formattedMonth}-01`;
    const endDate = new Date(year, month, 0).toISOString().split('T')[0];

    const { data: summary, error } = await supabase
      .rpc('get_monthly_summary', {
        start_date: startDate,
        end_date: endDate
      });

    if (error) throw error;

    // Ensure transportation_cost is always a number
    const processedSummary = summary.map(item => ({
      ...item,
      transportation_cost: item.transportation_cost || 0
    }));

    res.json(processedSummary);

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Add endpoint to get Ghana holidays
app.get('/api/holidays', authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('ghana_holidays')
      .select('*')
      .order('date', { ascending: true });

    if (error) throw error;
    res.json(data);

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Add this new endpoint
app.get('/api/overtime/check-duplicate', authenticateToken, async (req, res) => {
  try {
    const { worker_id, date } = req.query;

    if (!worker_id || !date) {
      return res.status(400).json({ error: 'Worker ID and date are required' });
    }

    // Query Supabase to check for existing entry
    const { data, error } = await supabase
      .from('overtime_entries')
      .select('id')
      .eq('worker_id', worker_id)
      .eq('date', date);

    if (error) {
      throw error;
    }

    // Check if we got any results
    const exists = Array.isArray(data) && data.length > 0;
    return res.json({ exists });

  } catch (error) {
    console.error('Error checking duplicate entry:', error);
    return res.status(500).json({ error: 'Failed to check for duplicate entry' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
  console.log(`Server is accessible`); 
});
