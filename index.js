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
  origin: process.env.FRONTEND_URL,
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
  body('role').isIn(['Standard', 'Supervisor', 'Accountant', 'Director', 'Developer']),
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password, secretCode, name, staffId, grade, role } = req.body;

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
          grade,
          role: role || 'Standard'
        }
      ])
      .select()
      .single();

    if (error) {
      console.error('Supabase error:', error);
      throw error;
    }

    // Generate JWT token with 12-hour expiration
    const token = jwt.sign(
      { id: admin.id, role: admin.role },
      process.env.JWT_SECRET,
      { expiresIn: '12h' }  // Token expires in 12 hours
    );

    res.json({
      token,
      user: {
        id: admin.id,
        name: admin.name,
        staffId: admin.staff_id,
        grade: admin.grade,
        role: admin.role
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

    // Generate JWT token with 12-hour expiration
    const token = jwt.sign(
      { id: admin.id, role: admin.role },
      process.env.JWT_SECRET,
      { expiresIn: '12h' }  // Token expires in 12 hours
    );

    res.json({
      token,
      user: {
        id: admin.id,
        name: admin.name,
        staffId: admin.staff_id,
        grade: admin.grade,
        role: admin.role
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
    // First get the worker to check their default area
    const { data: worker, error: workerError } = await supabase
      .from('workers')
      .select('*')
      .eq('id', req.body.worker_id)
      .single();



    // Get the rate for the worker's default area
    const { data: areaData, error: areaError } = await supabase
      .from('areas')
      .select('rate')
      .eq('default_area', worker.default_area)
      .single();


    // Set transportation_cost when transportation is true
    const transportation_cost = req.body.transportation ? areaData.rate : null;

    // Restore automatic calculation for initial entry creation
    const category_a_amount = req.body.category_a_hours ? req.body.category_a_hours * 2 : 0;
    const category_c_amount = req.body.category_c_hours ? req.body.category_c_hours * 3 : 0;

    const { data, error } = await supabase
      .from('overtime_entries')
      .insert([{
        worker_id: req.body.worker_id,
        date: req.body.date,
        entry_time: req.body.entry_time,
        exit_time: req.body.exit_time,
        category: req.body.category,
        category_a_hours: req.body.category_a_hours,
        category_c_hours: req.body.category_c_hours,
        category_a_amount: category_a_amount,
        category_c_amount: category_c_amount,
        transportation: req.body.transportation,
        transportation_cost: transportation_cost,
        approval_status: 'Pending',
        created_by: req.user.id
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
    res.status(500).json({ error: error.message });
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
        ),
        approved_by_admin:approved_by (
          name
        ),
        last_edited_by_admin:last_edited_by (
          name
        ),
        created_by
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

// Edit overtime entry
app.put('/api/overtime/:entryId', authenticateToken, async (req, res) => {
  try {
    const { entryId } = req.params;
    const { entry_time, exit_time, category_a_hours, category_c_hours, transportation, transportation_cost } = req.body;
    
    // Get the current entry to check approval status
    const { data: currentEntry, error: fetchError } = await supabase
      .from('overtime_entries')
      .select('approval_status')
      .eq('id', entryId)
      .single();
      
    if (fetchError) throw fetchError;
    
    // Get admin role from token
    const adminRole = req.user.role;
    
    // Check permission based on role and approval status
    let permissionDenied = false;
    
    // Standard admin can only edit pending entries
    if (adminRole === 'Standard' && currentEntry.approval_status !== 'Pending') {
      permissionDenied = true;
    }
    
    // Supervisor can edit pending entries and supervisor-approved entries
    if (adminRole === 'Supervisor' && 
        !['Pending', 'Supervisor'].includes(currentEntry.approval_status)) {
      permissionDenied = true;
    }
    
    // Accountant can edit everything except fully approved entries
    if (adminRole === 'Accountant' && currentEntry.approval_status === 'Approved') {
      permissionDenied = true;
    }
    
    if (permissionDenied) {
      return res.status(403).json({ 
        error: 'You do not have permission to edit this entry due to its approval status' 
      });
    }
    
    // Calculate amounts based on overtime formulas
    const category_a_amount = category_a_hours ? category_a_hours * 2 : 0;
    const category_c_amount = category_c_hours ? category_c_hours * 3 : 0;
    
    // Update the entry
    const updateData = {
      last_edited_by: req.user.id,
      last_edited_at: new Date().toISOString()
    };
    
    // Only update fields that were provided
    if (entry_time !== undefined) updateData.entry_time = entry_time;
    if (exit_time !== undefined) updateData.exit_time = exit_time;
    if (category_a_hours !== undefined) {
      updateData.category_a_hours = category_a_hours;
      updateData.category_a_amount = category_a_amount;
    }
    if (category_c_hours !== undefined) {
      updateData.category_c_hours = category_c_hours;
      updateData.category_c_amount = category_c_amount;
    }
    if (transportation !== undefined) updateData.transportation = transportation;
    
    // Accountant can update costs directly
    if (adminRole === 'Accountant') {
      if (transportation_cost !== undefined) {
        updateData.transportation_cost = transportation_cost;
      }
      if (req.body.category_a_amount !== undefined) {
        updateData.category_a_amount = req.body.category_a_amount;
      }
      if (req.body.category_c_amount !== undefined) {
        updateData.category_c_amount = req.body.category_c_amount;
      }
    }
    
    const { data, error } = await supabase
      .from('overtime_entries')
      .update(updateData)
      .eq('id', entryId)
      .select(`
        *,
        workers (
          name,
          staff_id,
          grade,
          default_area
        ),
        approved_by_admin:approved_by (
          name
        ),
        last_edited_by_admin:last_edited_by (
          name
        )
      `);
      
    if (error) throw error;
    
    res.json(data[0]);
    
  } catch (error) {
    console.error('Error updating overtime entry:', error);
    res.status(500).json({ error: error.message });
  }
});

// Approve overtime entry
app.put('/api/overtime/:entryId/approve', authenticateToken, async (req, res) => {
  try {
    const { entryId } = req.params;
    
    // Get the current entry to check approval status
    const { data: currentEntry, error: fetchError } = await supabase
      .from('overtime_entries')
      .select('approval_status, worker_id, date')
      .eq('id', entryId)
      .single();
      
    if (fetchError) throw fetchError;
    
    // Get admin role from token
    const adminRole = req.user.role;
    
    // Determine the new approval status based on admin role and current status
    let newApprovalStatus = currentEntry.approval_status;
    let canApprove = true;
    
    switch (adminRole) {
      case 'Standard':
        // Standard admin can mark pending entries as approved by standard
        if (currentEntry.approval_status === 'Pending') {
          newApprovalStatus = 'Standard';
        } else {
          canApprove = false;
        }
        break;
      case 'Supervisor':
        // Supervisor can only approve standard-approved entries
        if (currentEntry.approval_status === 'Standard') {
          newApprovalStatus = 'Supervisor';
        } else {
          canApprove = false;
        }
        break;
      case 'Director':
        // Director can only approve supervisor-approved entries
        if (currentEntry.approval_status === 'Supervisor') {
          newApprovalStatus = 'Approved';
        } else {
          canApprove = false;
        }
        break;
      default:
        // Any other role cannot approve
        canApprove = false;
        break;
    }
    
    if (!canApprove) {
      return res.status(403).json({
        error: 'You do not have permission to approve this entry in its current state'
      });
    }
    
    // Update the entry with new approval status
    const { data, error } = await supabase
      .from('overtime_entries')
      .update({
        approval_status: newApprovalStatus,
        approved_by: req.user.id,
        approved_at: new Date().toISOString()
      })
      .eq('id', entryId)
      .select(`
        *,
        workers (
          name,
          staff_id,
          grade,
          default_area
        ),
        approved_by_admin:approved_by (
          name
        ),
        last_edited_by_admin:last_edited_by (
          name
        )
      `);
      
    if (error) throw error;
    
    // After approving an entry, check if all entries for this worker in this month have been approved
    if (adminRole === 'Standard' && newApprovalStatus === 'Standard') {
      // Extract month and year from the entry date
      const entryDate = new Date(currentEntry.date);
      const month = entryDate.getMonth() + 1; // JavaScript months are 0-indexed
      const year = entryDate.getFullYear();
      
      await checkAndUpdateMonthlyStatus(currentEntry.worker_id, month, year);
    }
    
    res.json(data[0]);
    
  } catch (error) {
    console.error('Error approving overtime entry:', error);
    res.status(500).json({ error: error.message });
  }
});

// Helper function to set monthly status to Standard once all entries are approved by Standard
async function checkAndUpdateMonthlyStatus(workerId, month, year) {
  try {
    const formattedMonth = month.toString().padStart(2, '0');
    const startDate = `${year}-${formattedMonth}-01`;
    const endDate = new Date(year, parseInt(month), 0).toISOString().split('T')[0];
    
    // Get all entries for this worker in the selected month
    const { data: entries, error } = await supabase
      .from('overtime_entries')
      .select('id, approval_status')
      .eq('worker_id', workerId)
      .gte('date', startDate)
      .lte('date', endDate);
      
    if (error) throw error;
    
    if (!entries || entries.length === 0) {
      console.log(`[checkAndUpdateMonthlyStatus] No entries found for worker ${workerId} in ${month}/${year}`);
      return;
    }
    
    // Check if ANY entries are not at least Standard
    const allAtLeastStandard = entries.every(entry => 
      ['Standard', 'Supervisor', 'Accountant', 'Approved'].includes(entry.approval_status)
    );
    
    // Log the current status
    if (allAtLeastStandard) {
      console.log(`[checkAndUpdateMonthlyStatus] All entries for worker ${workerId} in ${month}/${year} are at least Standard.`);
    } else {
      console.log(`[checkAndUpdateMonthlyStatus] Not all entries for worker ${workerId} in ${month}/${year} are at Standard level yet.`);
    }
    
    // No automatic updates - require each entry to be explicitly approved by a user
  } catch (error) {
    console.error('[checkAndUpdateMonthlyStatus] Error:', error);
  }
}

// Reject overtime entry
app.put('/api/overtime/:entryId/reject', authenticateToken, async (req, res) => {
  try {
    const { entryId } = req.params;
    const { reason } = req.body;
    
    // Get admin role from token
    const adminRole = req.user.role;
    
    // Only supervisors and above can reject entries
    if (adminRole === 'Standard') {
      return res.status(403).json({
        error: 'Standard admins cannot reject entries'
      });
    }
    
    // Update the entry with rejected status
    const { data, error } = await supabase
      .from('overtime_entries')
      .update({
        approval_status: 'Rejected',
        rejection_reason: reason,
        rejected_by: req.user.id,
        rejected_at: new Date().toISOString()
      })
      .eq('id', entryId)
      .select(`
        *,
        workers (
          name,
          staff_id,
          grade,
          default_area
        ),
        rejected_by_admin:rejected_by (
          name
        )
      `);
      
    if (error) throw error;
    
    res.json(data[0]);
    
  } catch (error) {
    console.error('Error rejecting overtime entry:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get monthly summary with approval status
app.get('/api/summary/monthly', authenticateToken, async (req, res) => {
  try {
    const { month, year } = req.query;
    
    const formattedMonth = month.toString().padStart(2, '0');
    const startDate = `${year}-${formattedMonth}-01`;
    const endDate = new Date(year, month, 0).toISOString().split('T')[0];

    // Get the admin's role for filtering based on permissions
    const adminRole = req.user.role;
    
    // Build the query based on admin role
    let query = supabase
      .from('overtime_entries')
      .select(`
        id,
        worker_id,
        workers (
          name,
          staff_id,
          grade
        ),
        category_a_hours,
        category_c_hours,
        category_a_amount,
        category_c_amount,
        transportation,
        transportation_cost,
        approval_status,
        approved_by,
        approved_by_admin:approved_by (
          name
        ),
        last_edited_by,
        last_edited_by_admin:last_edited_by (
          name
        )
      `)
      .gte('date', startDate)
      .lte('date', endDate);
    
    // No role-based filtering - all roles can now see all approval statuses
    // Standard users can see all but only edit/approve pending
    // Supervisors can see all but only approve standard
    // Accountants can see all but only edit supervisor
    // Directors can see all but only approve accountant

    const { data: entries, error } = await query;

    if (error) throw error;

    // Process and summarize data
    const workerMap = new Map();
    
    entries.forEach(entry => {
      const workerId = entry.worker_id;
      
      if (!workerMap.has(workerId)) {
        workerMap.set(workerId, {
          worker_id: workerId,
          name: entry.workers.name,
          staff_id: entry.workers.staff_id,
          grade: entry.workers.grade,
          category_a_hours: 0,
          category_c_hours: 0,
          category_a_amount: 0,
          category_c_amount: 0,
          transportation_days: 0,
          transportation_cost: 0,
          entries: [],
          approval_statuses: [], // Track all statuses
          approval_status: 'Pending' // Default, will be updated
        });
      }
      
      const summary = workerMap.get(workerId);
      summary.category_a_hours += entry.category_a_hours || 0;
      summary.category_c_hours += entry.category_c_hours || 0;
      summary.category_a_amount += entry.category_a_amount || 0;
      summary.category_c_amount += entry.category_c_amount || 0;
      
      if (entry.transportation) {
        summary.transportation_days += 1;
        summary.transportation_cost += entry.transportation_cost || 0;
      }
      
      summary.entries.push({
        id: entry.id,
        approval_status: entry.approval_status,
        approved_by: entry.approved_by_admin?.name,
        last_edited_by: entry.last_edited_by_admin?.name
      });
      
      // Track all unique approval statuses for this worker
      if (!summary.approval_statuses.includes(entry.approval_status)) {
        summary.approval_statuses.push(entry.approval_status);
      }
    });
    
    // Calculate overall approval status for each worker based on refined rules
    workerMap.forEach(summary => {
      const statuses = summary.approval_statuses;
      
      if (!statuses || statuses.length === 0) {
        summary.approval_status = 'Pending'; 
        return;
      }

      // Priority 1: Pending - If any entry is pending, the whole month is pending.
      if (statuses.includes('Pending')) {
        summary.approval_status = 'Pending';
        return; // Stop further checks
      }

      // Count the number of entries in each status
      const statusCounts = {
        'Pending': 0,
        'Standard': 0,
        'Supervisor': 0,
        'Accountant': 0,
        'Approved': 0,
        'Rejected': 0
      };
      
      // Count occurrences of each status
      summary.entries.forEach(entry => {
        statusCounts[entry.approval_status]++;
      });
      
      const totalEntries = summary.entries.length;
      const nonRejectedEntries = totalEntries - statusCounts['Rejected'];
      
      // Only advance to a status if ALL non-rejected entries have reached at least that status
      if (nonRejectedEntries === 0) {
        summary.approval_status = 'Rejected';
      } 
      else if (statusCounts['Approved'] === nonRejectedEntries) {
        summary.approval_status = 'Approved';
      }
      else if (statusCounts['Approved'] + statusCounts['Accountant'] === nonRejectedEntries) {
        summary.approval_status = 'Accountant';
      }
      else if (statusCounts['Approved'] + statusCounts['Accountant'] + statusCounts['Supervisor'] === nonRejectedEntries) {
        summary.approval_status = 'Supervisor';
      }
      else if (statusCounts['Approved'] + statusCounts['Accountant'] + statusCounts['Supervisor'] + statusCounts['Standard'] === nonRejectedEntries) {
        summary.approval_status = 'Standard';
      }
      else {
        summary.approval_status = 'Pending';
      }
      
      // Add counts for debugging and UI display purposes
      summary.status_counts = statusCounts;
    });
    
    const summaries = Array.from(workerMap.values());
    res.json(summaries);

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

// Risk Management endpoints
// Get risk entries for a specific month and year
app.get('/api/risk', authenticateToken, async (req, res) => {
  try {
    const { month, year } = req.query;
    
    const formattedMonth = month.toString().padStart(2, '0');
    const startDate = `${year}-${formattedMonth}-01`;
    const endDate = new Date(year, month, 0).toISOString().split('T')[0];

    const { data, error } = await supabase
      .from('risk_entries')
      .select(`
        *,
        worker:worker_id (
          name,
          staff_id,
          grade
        )
      `)
      .gte('date', startDate)
      .lte('date', endDate)
      .order('date', { ascending: true });

    if (error) throw error;
    res.json(data);

  } catch (error) {
    console.error('Error fetching risk entries:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get risk summary by worker for a specific month and year
app.get('/api/risk/summary', authenticateToken, async (req, res) => {
  try {
    const { month, year } = req.query;
    
    const formattedMonth = month.toString().padStart(2, '0');
    const startDate = `${year}-${formattedMonth}-01`;
    const endDate = new Date(year, month, 0).toISOString().split('T')[0];

    // Get all entries for the period
    const { data: entries, error: entriesError } = await supabase
      .from('risk_entries')
      .select(`
        *,
        worker:worker_id (
          name,
          staff_id,
          grade
        )
      `)
      .gte('date', startDate)
      .lte('date', endDate);
    
    if (entriesError) throw entriesError;

    // Group and summarize by worker
    const workerMap = new Map();
    
    entries.forEach(entry => {
      const { worker_id, worker, rate } = entry;
      
      if (!workerMap.has(worker_id)) {
        workerMap.set(worker_id, {
          worker_id,
          name: worker.name,
          staff_id: worker.staff_id,
          grade: worker.grade,
          total_entries: 0,
          total_amount: 0
        });
      }
      
      const summary = workerMap.get(worker_id);
      summary.total_entries += 1;
      summary.total_amount += rate || 10.00;
    });
    
    const summaries = Array.from(workerMap.values());
    res.json(summaries);

  } catch (error) {
    console.error('Error fetching risk summary:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get risk summary for a specific worker by month and year
app.get('/api/risk/summary/:workerId', authenticateToken, async (req, res) => {
  try {
    const { workerId } = req.params;
    const { month, year } = req.query;
    
    const formattedMonth = month.toString().padStart(2, '0');
    const startDate = `${year}-${formattedMonth}-01`;
    const endDate = new Date(year, month, 0).toISOString().split('T')[0];
    
    // Get worker details
    const { data: worker, error: workerError } = await supabase
      .from('workers')
      .select('name, staff_id, grade')
      .eq('id', workerId)
      .single();
      
    if (workerError) throw workerError;
    
    // Get entries for this worker in the period
    const { data: entries, error: entriesError } = await supabase
      .from('risk_entries')
      .select('*')
      .eq('worker_id', workerId)
      .gte('date', startDate)
      .lte('date', endDate);
    
    if (entriesError) throw entriesError;
    
    // Calculate total amount
    let total_amount = 0;
    entries.forEach(entry => {
      total_amount += entry.rate || 10.00;
    });
    
    // Return summary
    res.json({
      worker_id: workerId,
      name: worker.name,
      staff_id: worker.staff_id,
      grade: worker.grade,
      total_entries: entries.length,
      total_amount
    });
    
  } catch (error) {
    console.error('Error fetching worker risk summary:', error);
    res.status(500).json({ error: error.message });
  }
});

// Create a new risk entry
app.post('/api/risk', authenticateToken, async (req, res) => {
  try {
    const { worker_id, date, location, size_depth, remarks, rate = 10.00 } = req.body;
    
    // Validate required fields
    if (!worker_id || !date || !location || !size_depth) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    // Insert the risk entry
    const { data, error } = await supabase
      .from('risk_entries')
      .insert([{
        worker_id,
        date,
        location,
        size_depth, 
        remarks,
        rate,
        created_by: req.user.id
      }])
      .select(`
        *,
        worker:worker_id (
          name,
          staff_id,
          grade
        ),
        created_by_admin:created_by (
             name
        ),
        last_edited_by_admin:last_edited_by (
             name
        )
      `);
    
    if (error) {
      console.error('Insert error:', error);
      throw error;
    }
    
    res.json(data[0]);
    
  } catch (error) {
    console.error('Error creating risk entry:', error);
    res.status(500).json({ error: error.message });
  }
});

// Worker signin
app.post('/api/worker/signin', [
  body('staffId').notEmpty(),
  body('pin').isLength({ min: 6, max: 6 }).isNumeric(),
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { staffId, pin } = req.body;

    // Get worker from database
    const { data: worker, error } = await supabase
      .from('workers')
      .select('*')
      .eq('staff_id', staffId)
      .single();

    if (error || !worker) {
      return res.status(400).json({ error: 'Worker not found' });
    }

    // Verify PIN
    const validPin = await bcrypt.compare(pin, worker.pin);
    if (!validPin) {
      return res.status(400).json({ error: 'Invalid PIN' });
    }

    // Generate JWT token with 12-hour expiration
    const token = jwt.sign(
      { id: worker.id, type: 'worker' },
      process.env.JWT_SECRET,
      { expiresIn: '12h' }  // Token expires in 12 hours
    );

    res.json({
      token,
      worker: {
        id: worker.id,
        name: worker.name,
        staffId: worker.staff_id,
        grade: worker.grade
      }
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Endpoint to set/reset worker PIN
app.post('/api/worker/setpin', authenticateToken, [
  body('workerId').notEmpty(),
  body('pin').isLength({ min: 6, max: 6 }).isNumeric(),
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    // Check if the requesting user is an admin
    if (req.user.role !== 'Standard' && 
        req.user.role !== 'Supervisor' && 
        req.user.role !== 'Accountant' && 
        req.user.role !== 'Director') {
      return res.status(403).json({ error: 'Only administrators can set worker PINs' });
    }

    const { workerId, pin } = req.body;

    // Hash the PIN
    const salt = await bcrypt.genSalt(10);
    const hashedPin = await bcrypt.hash(pin, salt);

    // Update the worker's PIN
    const { data, error } = await supabase
      .from('workers')
      .update({ pin: hashedPin })
      .eq('id', workerId)
      .select('staff_id, name');

    if (error) throw error;

    res.json({ 
      message: `PIN set successfully for worker ${data[0].name}`,
      workerId: data[0].staff_id 
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get worker summary
app.get('/api/workers/:id/summary', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { month, year } = req.query;

    // Convert month and year to integers for calculations
    const monthInt = parseInt(month);
    const yearInt = parseInt(year);
    
    if (isNaN(monthInt) || isNaN(yearInt)) {
      return res.status(400).json({ error: 'Invalid month or year' });
    }
    
    // Calculate date range for the given month and year
    const formattedMonth = monthInt.toString().padStart(2, '0');
    const startDate = `${yearInt}-${formattedMonth}-01`;
    // Calculate end date (last day of the month)
    const endDate = new Date(yearInt, monthInt, 0).toISOString().split('T')[0];
    
    console.log(`Fetching summary for worker ${id} from ${startDate} to ${endDate}`);

    // Get worker details
    const { data: worker, error: workerError } = await supabase
      .from('workers')
      .select('*')
      .eq('id', id)
      .single();

    if (workerError || !worker) {
      return res.status(404).json({ error: 'Worker not found' });
    }

    // Get overtime entries for the specified month and year using date range
    const { data: overtimeEntries, error: overtimeError } = await supabase
      .from('overtime_entries')
      .select('*')
      .eq('worker_id', id)
      .gte('date', startDate)
      .lte('date', endDate);

    if (overtimeError) {
      console.error('Error fetching overtime entries:', overtimeError);
      throw overtimeError;
    }
    
    console.log(`Found ${overtimeEntries?.length || 0} overtime entries for worker ${id}`);

    // Calculate summary data
    const summary = {
      category_a_hours: overtimeEntries.reduce((sum, entry) => sum + (entry.category_a_hours || 0), 0),
      category_c_hours: overtimeEntries.reduce((sum, entry) => sum + (entry.category_c_hours || 0), 0),
      transportation_days: overtimeEntries.filter(entry => entry.transportation).length,
      transportation_cost: overtimeEntries.reduce((sum, entry) => sum + (entry.transportation_cost || 0), 0),
      risk_entries: overtimeEntries.filter(entry => entry.risk_entry).length,
      avg_work_hours: overtimeEntries.length > 0 
        ? overtimeEntries.reduce((sum, entry) => sum + (entry.total_hours || 0), 0) / overtimeEntries.length
        : 0,
      total_entries: overtimeEntries.length
    };

    res.json({
      worker: {
        id: worker.id,
        name: worker.name,
        staff_id: worker.staff_id,
        grade: worker.grade,
        default_area: worker.default_area
      },
      summary
    });

  } catch (error) {
    console.error('Error fetching worker summary:', error);
    res.status(500).json({ error: 'Failed to fetch worker summary' });
  }
});

// Get worker by staff ID
app.get('/api/workers/staff/:staffId', authenticateToken, async (req, res) => {
  try {
    const { staffId } = req.params;

    // Ensure the requesting user is an admin or the worker themselves
    // (Add more specific role checks if needed)
    if (!req.user.role && req.user.type !== 'worker') {
       // Check if the requesting worker is asking for their own data
       const { data: requestingWorker } = await supabase
         .from('workers')
         .select('staff_id')
         .eq('id', req.user.id)
         .single();
       if (!requestingWorker || requestingWorker.staff_id !== staffId) {
         return res.status(403).json({ error: 'Permission denied' });
       }
    } else if (!['Standard', 'Supervisor', 'Accountant', 'Director'].includes(req.user.role) && req.user.type !== 'worker') {
         return res.status(403).json({ error: 'Permission denied' });
    }


    const { data: worker, error } = await supabase
      .from('workers')
      .select('*') // Select all columns or specific ones needed by frontend
      .eq('staff_id', staffId)
      .single();

    if (error) {
       console.error('Error fetching worker by staff ID:', error);
       // Differentiate between DB error and not found
       if (error.code === 'PGRST116') { // Supabase code for "Exactly one row expected" failure
          return res.status(404).json({ error: `Worker with staff ID ${staffId} not found` });
       }
       throw error; // Throw other DB errors
    }

    if (!worker) {
      return res.status(404).json({ error: `Worker with staff ID ${staffId} not found` });
    }

    res.json(worker);

  } catch (error) {
    console.error('Server error fetching worker by staff ID:', error);
    res.status(500).json({ error: 'Failed to fetch worker data' });
  }
});

// Get current clock status for the authenticated worker
app.get('/api/clock/status', authenticateToken, async (req, res) => {
  try {
    // Ensure the request is from a worker
    if (req.user.type !== 'worker' || !req.user.id) {
      return res.status(403).json({ error: 'Access denied. Only workers can check clock status.' });
    }

    const workerId = req.user.id;

    // Find the latest clock entry for this worker
    const { data: latestEntry, error: entryError } = await supabase
      .from('clock_entries')
      .select('*') // Select all fields to access location data
      .eq('worker_id', workerId)
      .order('clock_in_time', { ascending: false }) // Get the most recent first
      .limit(1)
      .single();

    if (entryError && entryError.code !== 'PGRST116') { // Ignore 'PGRST116' (no rows found)
       console.error('Error fetching latest clock entry:', entryError);
       throw entryError;
    }

    let status = 'clocked_out'; // Default status
    let lastEvent = null;

    if (latestEntry) {
      if (!latestEntry.clock_out_time) {
        // If the latest entry exists and has no clock_out_time, they are clocked in
        status = 'clocked_in';
        
        // Last event is clock in
        lastEvent = {
          type: 'in',
          timestamp: latestEntry.clock_in_time,
          location: latestEntry.clock_in_location || null
        };
      } else {
        // Last event is clock out
        lastEvent = {
          type: 'out',
          timestamp: latestEntry.clock_out_time,
          location: latestEntry.clock_out_location || null
        };
      }
    }

    // Check that location data exists and is valid
    if (lastEvent && lastEvent.location) {
      console.log('Last event location data:', lastEvent.location);
    }

    res.json({ status, lastEvent });

  } catch (error) {
    console.error('Error fetching clock status:', error);
    res.status(500).json({ error: 'Failed to fetch clock status' });
  }
});

// Update monthly amounts for a worker
app.put('/api/summary/monthly/:workerId', authenticateToken, async (req, res) => {
  try {
    const { workerId } = req.params;
    const { month, year, category_a_amount, category_c_amount, transportation_cost } = req.body;
    
    // Verify required fields
    if (!month || !year) {
      return res.status(400).json({ error: 'Month and year are required' });
    }

    // Format month string with leading zero if needed
    const formattedMonth = month.toString().padStart(2, '0');
    
    // Calculate start and end dates for the month
    const startDate = `${year}-${formattedMonth}-01`;
    const endDate = new Date(year, parseInt(month), 0).toISOString().split('T')[0];
    
    // Get all entries for this worker in the specified month
    const { data: entries, error: getError } = await supabase
      .from('overtime_entries')
      .select('*')
      .eq('worker_id', workerId)
      .gte('date', startDate)
      .lte('date', endDate);
    
    if (getError) {
      console.error('Error fetching entries:', getError);
      return res.status(500).json({ error: 'Failed to fetch entries' });
    }
    
    // If no entries found, return error
    if (!entries || entries.length === 0) {
      return res.status(404).json({ error: 'No entries found for the specified month' });
    }
    
    // Calculate current totals
    const currentTotals = entries.reduce((acc, entry) => ({
      category_a_hours: acc.category_a_hours + (entry.category_a_hours || 0),
      category_c_hours: acc.category_c_hours + (entry.category_c_hours || 0),
      category_a_amount: acc.category_a_amount + (entry.category_a_amount || 0),
      category_c_amount: acc.category_c_amount + (entry.category_c_amount || 0),
      transportation_count: acc.transportation_count + (entry.transportation ? 1 : 0),
      transportation_cost: acc.transportation_cost + (entry.transportation ? (entry.transportation_cost || 0) : 0)
    }), {
      category_a_hours: 0,
      category_c_hours: 0,
      category_a_amount: 0,
      category_c_amount: 0,
      transportation_count: 0,
      transportation_cost: 0
    });
    
    // Set up batch update for all entries
    const updates = [];
    
    // Distribute the new amounts proportionally
    for (const entry of entries) {
      const newEntry = { ...entry };
      
      // Calculate proportional rates for Category A
      if (currentTotals.category_a_hours > 0 && category_a_amount !== undefined) {
        const proportion = (entry.category_a_hours || 0) / currentTotals.category_a_hours;
        newEntry.category_a_amount = proportion * category_a_amount;
      }
      
      // Calculate proportional rates for Category C
      if (currentTotals.category_c_hours > 0 && category_c_amount !== undefined) {
        const proportion = (entry.category_c_hours || 0) / currentTotals.category_c_hours;
        newEntry.category_c_amount = proportion * category_c_amount;
      }
      
      // Calculate proportional rates for transportation
      if (entry.transportation && currentTotals.transportation_count > 0 && transportation_cost !== undefined) {
        const transportProportion = 1 / currentTotals.transportation_count;
        newEntry.transportation_cost = transportProportion * transportation_cost;
      }
      
      // Add to update batch if values changed
      if (
        newEntry.category_a_amount !== entry.category_a_amount ||
        newEntry.category_c_amount !== entry.category_c_amount ||
        newEntry.transportation_cost !== entry.transportation_cost
      ) {
        updates.push({
          id: entry.id,
          category_a_amount: newEntry.category_a_amount,
          category_c_amount: newEntry.category_c_amount,
          transportation_cost: entry.transportation ? newEntry.transportation_cost : entry.transportation_cost,
          last_edited_by: req.user.id,
          last_edited_at: new Date()
        });
      }
    }
    
    // If there are updates, apply them
    if (updates.length > 0) {
      // Update each entry individually to avoid NOT NULL constraint issues
      for (const update of updates) {
        const { error: updateError } = await supabase
          .from('overtime_entries')
          .update({
            category_a_amount: update.category_a_amount,
            category_c_amount: update.category_c_amount,
            transportation_cost: update.transportation_cost,
            last_edited_by: update.last_edited_by,
            last_edited_at: update.last_edited_at
          })
          .eq('id', update.id);
        if (updateError) {
          console.error('Error updating entry:', updateError);
          return res.status(500).json({ error: 'Failed to update entries' });
        }
      }
    }
    
    // Return success
    return res.json({ 
      message: 'Monthly summary updated successfully',
      updates_count: updates.length
    });
  } catch (error) {
    console.error('Error updating monthly summary:', error);
    return res.status(500).json({ error: 'An unexpected error occurred' });
  }
});

// Approve monthly summary for a worker
app.put('/api/summary/monthly/:workerId/approve', authenticateToken, async (req, res) => {
  try {
    const { workerId } = req.params;
    const { month, year } = req.body;
    
    // Get admin role from token
    const adminRole = req.user.role;
    
    // Define the new status and required current status based on the admin's role
    let newStatus = '';
    let requiredCurrentStatus = '';
    let canApprove = true;
    
    switch (adminRole) {
      case 'Supervisor':
        newStatus = 'Supervisor';
        requiredCurrentStatus = 'Standard';
        break;
      case 'Director':
        newStatus = 'Approved';
        requiredCurrentStatus = 'Supervisor';
        break;
      default:
        canApprove = false;
    }
    
    if (!canApprove) {
      return res.status(403).json({
        error: 'You do not have permission to approve entries'
      });
    }
    
    const formattedMonth = month.toString().padStart(2, '0');
    const startDate = `${year}-${formattedMonth}-01`;
    const endDate = new Date(year, parseInt(month), 0).toISOString().split('T')[0];
    
    // Find entries that match the criteria for approval
    const { data: entriesToApprove, error: findError } = await supabase
      .from('overtime_entries')
      .select('id') // Only need IDs to update
      .eq('worker_id', workerId)
      .gte('date', startDate)
      .lte('date', endDate)
      .eq('approval_status', requiredCurrentStatus);
      
    if (findError) {
      console.error('Error finding entries to approve:', findError);
      throw findError;
    }
      
    if (!entriesToApprove || entriesToApprove.length === 0) {
      return res.json({
        message: `No entries found with status '${requiredCurrentStatus}' to approve for this period.`,
        updatedEntries: []
      });
    }
    
    const entryIdsToApprove = entriesToApprove.map(entry => entry.id);
    
    console.log(`Found ${entryIdsToApprove.length} entries with status '${requiredCurrentStatus}' to approve.`);
    
    // Update these entries
    const { data: updatedEntries, error: updateError } = await supabase
      .from('overtime_entries')
      .update({
        approval_status: newStatus,
        approved_by: req.user.id,
        approved_at: new Date().toISOString()
      })
      .in('id', entryIdsToApprove) // Use .in() to update specific entries
      .select(); // Select the updated entries
        
    if (updateError) {
      console.error('Error updating entries during approval:', updateError);
      throw updateError;
    }
      
    return res.json({
      message: `Successfully approved ${updatedEntries.length} entries for worker ${workerId} to status '${newStatus}'`,
      updatedEntries
    });

  } catch (error) {
    console.error('Error approving entries:', error);
    // Ensure a consistent error response format
    res.status(500).json({ 
        error: error.message || 'An unexpected error occurred during approval' 
    });
  }
});

// Add endpoint for Director bulk approval
app.put('/api/summary/monthly/approve-all-director', authenticateToken, async (req, res) => {
  try {
    const { month, year } = req.body;
    
    // Ensure this action is performed only by a Director
    if (req.user.role !== 'Director') {
      return res.status(403).json({ error: 'Permission denied. Only Directors can perform bulk approval.' });
    }
    
    const formattedMonth = month.toString().padStart(2, '0');
    const startDate = `${year}-${formattedMonth}-01`;
    const endDate = new Date(year, parseInt(month), 0).toISOString().split('T')[0];
    
    // Find all entries with 'Supervisor' status for the given month/year
    const { data: entriesToApprove, error: findError } = await supabase
      .from('overtime_entries')
      .select('id') // Only need IDs
      .gte('date', startDate)
      .lte('date', endDate)
      .eq('approval_status', 'Supervisor');
      
    if (findError) {
      console.error('Error finding Supervisor-approved entries for bulk approval:', findError);
      throw findError;
    }
    
    if (!entriesToApprove || entriesToApprove.length === 0) {
      return res.json({
        message: 'No Supervisor-approved entries found for this period to approve.',
        updatedEntries: []
      });
    }
    
    const entryIdsToApprove = entriesToApprove.map(entry => entry.id);
    console.log(`Director bulk approving ${entryIdsToApprove.length} Supervisor-approved entries.`);
    
    // Update these entries to 'Approved' status
    const { data: updatedEntries, error: updateError } = await supabase
      .from('overtime_entries')
      .update({
        approval_status: 'Approved', // Final approved status
        approved_by: req.user.id, // Record the Director as the approver
        approved_at: new Date().toISOString()
      })
      .in('id', entryIdsToApprove)
      .select(); // Select the updated entries
      
    if (updateError) {
      console.error('Error during Director bulk approval update:', updateError);
      throw updateError;
    }
    
    return res.json({
      message: `Successfully bulk approved ${updatedEntries.length} entries to 'Approved' status.`,
      updatedEntries
    });

  } catch (error) {
    console.error('Error during Director bulk approval:', error);
    res.status(500).json({ 
        error: error.message || 'An unexpected error occurred during bulk approval' 
    });
  }
});

// Clock In endpoint
app.post('/api/clock/in', authenticateToken, async (req, res) => {
  try {
    // Ensure the request is from a worker
    if (req.user.type !== 'worker') {
      return res.status(403).json({ error: 'Only workers can clock in' });
    }

    const workerId = req.user.id;
    const { latitude, longitude } = req.body;

    // More strict validation for location data
    if (latitude === undefined || longitude === undefined || latitude === null || longitude === null) {
      return res.status(400).json({ 
        error: 'Location data is required. Please enable location services and try again.'
      });
    }

    // Validate that coordinates are valid numbers in reasonable ranges
    const parsedLat = parseFloat(latitude);
    const parsedLng = parseFloat(longitude);
    
    if (isNaN(parsedLat) || isNaN(parsedLng) || 
        parsedLat < -90 || parsedLat > 90 || 
        parsedLng < -180 || parsedLng > 180) {
      return res.status(400).json({ 
        error: 'Invalid location coordinates. Please try again or contact support.'
      });
    }

    // Check if worker is already clocked in
    const { data: existingActiveEntry, error: activeCheckError } = await supabase
      .from('clock_entries')
      .select('*')
      .eq('worker_id', workerId)
      .is('clock_out_time', null)
      .single();

    if (existingActiveEntry) {
      return res.status(400).json({ error: 'You are already clocked in' });
    }

    // Check if worker has already completed a clock in/out cycle today
    const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD format
    const startOfDay = `${today}T00:00:00.000Z`;
    const endOfDay = `${today}T23:59:59.999Z`;

    const { data: todaysEntries, error: todayCheckError } = await supabase
      .from('clock_entries')
      .select('*')
      .eq('worker_id', workerId)
      .gte('clock_in_time', startOfDay)
      .lte('clock_in_time', endOfDay)
      .not('clock_out_time', 'is', null) // Only get entries that have been clocked out
      .order('clock_in_time', { ascending: false });

    if (todaysEntries && todaysEntries.length > 0) {
      return res.status(400).json({ 
        error: 'You have already completed your clock in/out for today. Only one clock in is allowed per day.' 
      });
    }

    // Get worker details for default area and transportation requirements
    const { data: worker, error: workerError } = await supabase
      .from('workers')
      .select('*')
      .eq('id', workerId)
      .single();
      
    if (workerError) {
      throw workerError;
    }

    // Ensure location data is properly formatted
    const locationData = {
      latitude: parsedLat,
      longitude: parsedLng
    };

    // Create new clock entry
    const now = new Date(); // Use Date object for easier manipulation
    const nowISOString = now.toISOString(); // Keep original ISO string for accurate timestamp
    
    // Apply rounding logic to clock in time
    let clockInHour = now.getHours();
    let clockInMinute = now.getMinutes();
    
    if (clockInMinute > 15) {
      clockInHour = (clockInHour + 1) % 24; // Increment hour, wrap around midnight
      clockInMinute = 0;
    } else {
      clockInMinute = 0; // Set minutes to 0 if not rounded up
    }
    
    // Create a new Date object with the rounded time for DB insertion
    const roundedClockInTime = new Date(now);
    roundedClockInTime.setHours(clockInHour);
    roundedClockInTime.setMinutes(clockInMinute);
    roundedClockInTime.setSeconds(0);
    roundedClockInTime.setMilliseconds(0);

    const { data, error } = await supabase
      .from('clock_entries')
      .insert([{
        worker_id: workerId,
        clock_in_time: roundedClockInTime.toISOString(), // Use rounded time for the entry
        clock_in_location: locationData
      }])
      .select()
      .single();

    if (error) {
      throw error;
    }
    
    // Also log the event in clock_events table for more detailed tracking
    const { data: eventData, error: eventError } = await supabase
      .from('clock_events')
      .insert([{
        worker_id: workerId,
        event_type: 'clock_in',
        timestamp: nowISOString, // Use the original timestamp for the event log
        location_latitude: parsedLat,
        location_longitude: parsedLng
      }])
      .select();

    res.json({
      ...data,
      message: "Clock in successful. You may clock out when your shift is complete."
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to clock in' });
  }
});

// Clock Out endpoint
app.post('/api/clock/out', authenticateToken, async (req, res) => {
  try {
    // Ensure the request is from a worker
    if (req.user.type !== 'worker') {
      return res.status(403).json({ error: 'Only workers can clock out' });
    }

    const workerId = req.user.id;
    const { latitude, longitude } = req.body;
    
    console.log(`Clock out attempt for worker ${workerId} with location data:`, { latitude, longitude });

    // More strict validation for location data
    if (latitude === undefined || longitude === undefined || latitude === null || longitude === null) {
      console.error(`Clock out failed for worker ${workerId}: Missing location data`);
      return res.status(400).json({ 
        error: 'Location data is required. Please enable location services and try again.'
      });
    }

    // Validate that coordinates are valid numbers in reasonable ranges
    const parsedLat = parseFloat(latitude);
    const parsedLng = parseFloat(longitude);
    
    if (isNaN(parsedLat) || isNaN(parsedLng) || 
        parsedLat < -90 || parsedLat > 90 || 
        parsedLng < -180 || parsedLng > 180) {
      console.error(`Clock out failed for worker ${workerId}: Invalid coordinates`, { latitude, longitude });
      return res.status(400).json({ 
        error: 'Invalid location coordinates. Please try again or contact support.'
      });
    }

    // Find the active clock entry
    const { data: activeEntry, error: findError } = await supabase
      .from('clock_entries')
      .select('*')
      .eq('worker_id', workerId)
      .is('clock_out_time', null)
      .single();

    if (!activeEntry) {
      console.log(`Worker ${workerId} attempted to clock out but has no active clock in`);
      return res.status(400).json({ error: 'No active clock in found' });
    }

    // Get the worker's default area and transportation requirement
    const { data: worker, error: workerError } = await supabase
      .from('workers')
      .select('*')
      .eq('id', workerId)
      .single();
      
    if (workerError) {
      console.error(`Error fetching worker ${workerId} details:`, workerError);
      throw workerError;
    }
    
    // We'll assume all workers need transportation by default
    const needsTransportation = worker.transport_required !== false;
    console.log(`Worker ${workerId} transportation required: ${needsTransportation}`);

    // Ensure location data is properly formatted
    const locationData = {
      latitude: parsedLat,
      longitude: parsedLng
    };

    console.log(`Clock out for worker ${workerId} with validated location:`, locationData);

    // Update the entry with clock out time and location
    const now = new Date(); // Use Date object for easier manipulation
    const nowISOString = now.toISOString(); // Keep ISO string for DB timestamp
    
    // Apply rounding logic to clock out time
    let clockOutHour = now.getHours();
    let clockOutMinute = now.getMinutes();
    
    if (clockOutMinute > 15) {
      clockOutHour = (clockOutHour + 1) % 24; // Increment hour, wrap around midnight
      clockOutMinute = 0;
    } else {
      // Keep the original hour but set minutes to 0 if <= 15. Or maybe keep original hour and minutes if <= 15? Let's keep original hour and minutes if <= 15 for now, only round up if > 15.
      // Re-reading the request: "I dont want overtime clock in enteries to have minutes just like the admin entry." This implies *all* minutes should be zeroed out if not rounded up.
      // Let's clarify: round up if > 15, otherwise set minutes to 00.
      clockOutMinute = 0; // Set minutes to 0 if not rounded up
    }
    
    // Create a new Date object with the rounded time for HH:MM extraction
    const roundedClockOutTime = new Date(now);
    roundedClockOutTime.setHours(clockOutHour);
    roundedClockOutTime.setMinutes(clockOutMinute);
    roundedClockOutTime.setSeconds(0);
    roundedClockOutTime.setMilliseconds(0);


    const { data, error } = await supabase
      .from('clock_entries')
      .update({
        clock_out_time: nowISOString, // Use original ISO string for accurate timestamp
        clock_out_location: locationData
      })
      .eq('id', activeEntry.id)
      .select()
      .single();

    if (error) {
      throw error;
    }
    
    // Also log the event in clock_events table for more detailed tracking
    const { data: eventData, error: eventError } = await supabase
      .from('clock_events')
      .insert([{
        worker_id: workerId,
        event_type: 'clock_out',
        timestamp: nowISOString,
        location_latitude: parsedLat,
        location_longitude: parsedLng
      }])
      .select();

    // Calculate hours worked and determine if overtime applies
    const clockInTime = new Date(activeEntry.clock_in_time);
    const clockOutTime = new Date(now);
    const hoursWorked = (clockOutTime.getTime() - clockInTime.getTime()) / (1000 * 60 * 60);

    // Create today's date in YYYY-MM-DD format
    const today = clockOutTime.toISOString().split('T')[0];
    
    // Check if an overtime entry already exists for today
    const { data: existingEntry, error: entryCheckError } = await supabase
      .from('overtime_entries')
      .select('*')
      .eq('worker_id', workerId)
      .eq('date', today)
      .maybeSingle();

    // Calculate overtime if applicable
    let overtimeHours = 0;
    let roundedOvertimeHours = 0;
    
    if (hoursWorked > 9) {
      overtimeHours = hoursWorked - 9; 
      // Round up partial hours to next whole hour
      roundedOvertimeHours = Math.ceil(overtimeHours);
    }

    // Get transportation cost from worker's default area
    let transportationCost = 10.0; // Default fallback rate
    
    if (worker.default_area) {
      // Get the rate from areas table using the default_area field
      const { data: areaData, error: areaError } = await supabase
        .from('areas')
        .select('rate')
        .eq('default_area', worker.default_area)
        .maybeSingle();
        
      if (!areaError && areaData && areaData.rate) {
        transportationCost = areaData.rate;
      }
    }

    // Format the entry/exit times to HH:MM format for overtime entries
    // Use the original clock-in time
    const entryTime = activeEntry.clock_in_time.split('T')[1].substring(0, 5); // Extract HH:MM
    // Use the rounded clock-out time
    const exitTime = roundedClockOutTime.toISOString().split('T')[1].substring(0, 5); // Extract HH:MM from rounded time

    // Determine if today is a weekend or holiday to set the correct category
    const todayDate = new Date(today);
    const dayOfWeek = todayDate.getDay(); // 0 = Sunday, 6 = Saturday
    const isWeekend = dayOfWeek === 0 || dayOfWeek === 6;
    
    // Check Ghana holidays table
    const { data: holidayData, error: holidayError } = await supabase
      .from('ghana_holidays')
      .select('*')
      .eq('date', today)
      .maybeSingle();
      
    const isHoliday = !holidayError && holidayData;
    
    // Set category based on weekday/weekend and holiday status
    // If it's a weekday and not a holiday: Category A
    // If it's a weekend or a holiday: Category C
    const category = (isWeekend || isHoliday) ? 'C' : 'A';

    try {
    if (existingEntry) {
      // Update existing entry with new data
      
      const updateData = {
        last_edited_at: nowISOString, // Use the original ISO string
        last_edited_by: '00000000-0000-0000-0000-000000000000', // System admin account
        // Set the category based on day type
        category: category,
        // Always update transportation since this is a successful clock-out
        transportation: true,
        transportation_cost: transportationCost,
        automatically_generated: true, // Flag entries created through the clock system
        // Update entry/exit time if they're not already set - always update now with calculated times
        entry_time: entryTime,
        exit_time: exitTime
      };
      
      // Add overtime if applicable
      if (roundedOvertimeHours > 0) {
          if (category === 'A') {
            // Category A rate is 2x
        updateData.category_a_hours = (existingEntry.category_a_hours || 0) + roundedOvertimeHours;
            updateData.category_a_amount = updateData.category_a_hours * 2;
            // Keep Category C as is
            updateData.category_c_hours = existingEntry.category_c_hours || 0;
            updateData.category_c_amount = existingEntry.category_c_amount || 0;
          } else { // Category C
            // Category C rate is 3x
            updateData.category_c_hours = (existingEntry.category_c_hours || 0) + roundedOvertimeHours;
            updateData.category_c_amount = updateData.category_c_hours * 3;
            // Keep Category A as is
            updateData.category_a_hours = existingEntry.category_a_hours || 0;
            updateData.category_a_amount = existingEntry.category_a_amount || 0;
          }
      }
      
      const { data: updatedEntry, error: updateError } = await supabase
        .from('overtime_entries')
        .update(updateData)
        .eq('id', existingEntry.id)
        .select();
        
      if (updateError) {
          throw updateError;
      }
    } else {
      // Create new overtime entry - always create one even without overtime to track transport
      
      const entryData = {
        worker_id: workerId,
        date: today,
        category: category, // Set the category based on day type (A or C)
        category_a_hours: category === 'A' ? roundedOvertimeHours : 0,
        category_a_amount: category === 'A' ? roundedOvertimeHours * 2 : 0, // Category A rate is 2x
        category_c_hours: category === 'C' ? roundedOvertimeHours : 0,
        category_c_amount: category === 'C' ? roundedOvertimeHours * 3 : 0, // Category C rate is 3x
        transportation: true, // Always set transport to true for successful clock-outs
        transportation_cost: transportationCost,
        approval_status: 'Pending',
        automatically_generated: true, // Flag entries created through the clock system
        created_by: '00000000-0000-0000-0000-000000000000', // System admin account
        entry_time: entryTime,
        exit_time: exitTime
      };
      
      const { data: newEntry, error: createError } = await supabase
        .from('overtime_entries')
        .insert([entryData])
        .select();
        
      if (createError) {
          throw createError;
      }
    }

    // Return success response with the updated clock entry
    res.json({
      ...data,
      message: "Clock out successful. Transportation entry has been added."
    });
    } catch (error) {
      console.error('Error creating/updating overtime entry:', error);
      // Continue with response even if overtime entry fails
      res.json({
        ...data,
        message: "Clock out successful, but failed to create transportation entry. Please add it manually."
      });
    }
  } catch (error) {
    console.error('Clock out error:', error);
    res.status(500).json({ error: 'Failed to clock out' });
  }
});

// Get clock history endpoint
app.get('/api/clock/history', authenticateToken, async (req, res) => {
  try {
    // Ensure the request is from a worker
    if (req.user.type !== 'worker') {
      return res.status(403).json({ error: 'Access denied' });
    }

    const workerId = req.user.id;

    const { data, error } = await supabase
      .from('clock_entries')
      .select('*')
      .eq('worker_id', workerId)
      .order('clock_in_time', { ascending: false })
      .limit(30); // Get last 30 entries

    if (error) throw error;

    // Format the data for frontend
    const formattedData = data.map(entry => ({
      type: entry.clock_out_time ? 'out' : 'in',
      timestamp: entry.clock_out_time || entry.clock_in_time,
      location: entry.clock_out_time ? entry.clock_out_location : entry.clock_in_location
    }));

    res.json(formattedData);
  } catch (error) {
    console.error('Error fetching clock history:', error);
    res.status(500).json({ error: 'Failed to fetch clock history' });
  }
});

// Delete overtime entry (Standard admin can only delete entries they created)
app.delete('/api/overtime/:entryId', authenticateToken, async (req, res) => {
  try {
    const { entryId } = req.params;
    const adminId = req.user.id;
    const adminRole = req.user.role;

    // Fetch the entry to check creator and status
    const { data: entry, error: fetchError } = await supabase
      .from('overtime_entries')
      .select('created_by, approval_status')
      .eq('id', entryId)
      .single();

    if (fetchError) {
      if (fetchError.code === 'PGRST116') {
        return res.status(404).json({ error: 'Overtime entry not found' });
      }
      throw fetchError;
    }

    // Permission check: Standard role can delete any PENDING or REJECTED entries
    if (adminRole === 'Standard' && !['Pending', 'Rejected'].includes(entry.approval_status)) {
      return res.status(403).json({ error: 'Standard admins can only delete Pending or Rejected entries.' });
    }
    
    // Supervisors and above can delete any entry regardless of status or creator
    if (!['Standard', 'Supervisor', 'Accountant', 'Director'].includes(adminRole)) {
        return res.status(403).json({ error: 'Permission denied.' });
    }
    
    // Allow Supervisor+ roles even if they didn't create it or it's not pending
    if (adminRole !== 'Standard' && !['Pending', 'Rejected'].includes(entry.approval_status)) {
        // Log this action? Maybe not necessary unless required
    }

    // Perform the deletion
    const { error: deleteError } = await supabase
      .from('overtime_entries')
      .delete()
      .eq('id', entryId);

    if (deleteError) throw deleteError;

    res.status(200).json({ message: 'Overtime entry deleted successfully' });

  } catch (error) {
    console.error('Error deleting overtime entry:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get risk entries for a specific worker and period
app.get('/api/risk/:workerId', authenticateToken, async (req, res) => {
  try {
    const { workerId } = req.params;
    const { month, year } = req.query;

    if (!month || !year) {
      return res.status(400).json({ error: 'Month and year query parameters are required' });
    }

    const formattedMonth = month.toString().padStart(2, '0');
    const startDate = `${year}-${formattedMonth}-01`;
    const endDate = new Date(year, month, 0).toISOString().split('T')[0];

    const { data, error } = await supabase
      .from('risk_entries')
      .select(`
        *,
        worker:worker_id (
          name,
          staff_id,
          grade
        )
      `)
      .eq('worker_id', workerId)
      .gte('date', startDate)
      .lte('date', endDate)
      .order('date', { ascending: true });

    if (error) throw error;
    res.json(data);

  } catch (error) {
    console.error('Error fetching risk entries for worker:', error);
    res.status(500).json({ error: error.message });
  }
});

// Update a risk entry
app.put('/api/risk/:entryId', authenticateToken, async (req, res) => {
  try {
    const { entryId } = req.params;
    const adminId = req.user.id;
    const adminRole = req.user.role;
    const { location, size_depth, remarks, rate } = req.body;

    // Fetch the entry to check creator
    const { data: entry, error: fetchError } = await supabase
      .from('risk_entries')
      .select('created_by')
      .eq('id', entryId)
      .single();

    if (fetchError) {
      if (fetchError.code === 'PGRST116') {
        return res.status(404).json({ error: 'Risk entry not found' });
      }
      throw fetchError;
    }

    // Permission check: Standard role can only edit their own entries. Supervisor+ can edit any.
    if (adminRole === 'Standard' && entry.created_by !== adminId) {
      return res.status(403).json({ error: 'Standard admins can only edit entries they created.' });
    }
    if (!['Standard', 'Supervisor', 'Accountant', 'Director'].includes(adminRole)) {
      return res.status(403).json({ error: 'Permission denied.' });
    }

    // Prepare update data - only include fields that are provided
    const updateData = {
      last_edited_by: adminId,
      last_edited_at: new Date().toISOString()
    };
    if (location !== undefined) updateData.location = location;
    if (size_depth !== undefined) updateData.size_depth = size_depth;
    if (remarks !== undefined) updateData.remarks = remarks;
    if (rate !== undefined && ['Supervisor', 'Accountant', 'Director'].includes(adminRole)) {
        // Only higher roles can update the rate directly? Or maybe just Accountant/Director? Let's allow Supervisor+ for now.
        updateData.rate = rate;
    }


    // Perform the update
    const { data: updatedEntry, error: updateError } = await supabase
      .from('risk_entries')
      .update(updateData)
      .eq('id', entryId)
      .select(`
        *,
        worker:worker_id (
          name,
          staff_id,
          grade
        ),
        last_edited_by_admin:last_edited_by (
             name
        )
      `);

    if (updateError) throw updateError;

    res.json(updatedEntry[0]);

  } catch (error) {
    console.error('Error updating risk entry:', error);
    res.status(500).json({ error: error.message });
  }
});

// Delete a risk entry
app.delete('/api/risk/:entryId', authenticateToken, async (req, res) => {
  try {
    const { entryId } = req.params;
    const adminId = req.user.id;
    const adminRole = req.user.role;

    // Fetch the entry to check creator
    const { data: entry, error: fetchError } = await supabase
      .from('risk_entries')
      .select('created_by')
      .eq('id', entryId)
      .single();

    if (fetchError) {
      if (fetchError.code === 'PGRST116') {
        return res.status(404).json({ error: 'Risk entry not found' });
      }
      throw fetchError;
    }

    // Permission check: Standard role can only delete their own entries. Supervisor+ can delete any.
    if (adminRole === 'Standard' && entry.created_by !== adminId) {
      return res.status(403).json({ error: 'Standard admins can only delete entries they created.' });
    }
     if (!['Standard', 'Supervisor', 'Accountant', 'Director'].includes(adminRole)) {
       return res.status(403).json({ error: 'Permission denied.' });
     }

    // Perform the deletion
    const { error: deleteError } = await supabase
      .from('risk_entries')
      .delete()
      .eq('id', entryId);

    if (deleteError) throw deleteError;

    res.status(200).json({ message: 'Risk entry deleted successfully' });

  } catch (error) {
    console.error('Error deleting risk entry:', error);
    res.status(500).json({ error: error.message });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  // Remove console.error for error stack
  res.status(500).json({ error: 'Something went wrong!' });
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  // Remove console.log for server startup
});

// Endpoint to assign Developer role to an existing admin
app.post('/api/admin/developer-role', [
  body('email').isEmail(),
  body('secretCode').notEmpty(),
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, secretCode } = req.body;

    // Verify secret code
    if (secretCode !== process.env.ADMIN_SECRET_CODE) {
      return res.status(403).json({ error: 'Invalid secret code' });
    }

    // Check if admin exists
    const { data: existingAdmin, error: findError } = await supabase
      .from('admins')
      .select('id, email, role')
      .eq('email', email)
      .single();

    if (findError || !existingAdmin) {
      return res.status(404).json({ error: 'Admin not found' });
    }

    // Update the admin role to Developer
    const { data: updatedAdmin, error: updateError } = await supabase
      .from('admins')
      .update({ role: 'Developer' })
      .eq('id', existingAdmin.id)
      .select()
      .single();

    if (updateError) {
      console.error('Supabase error:', updateError);
      throw updateError;
    }

    res.json({
      success: true,
      message: `Role updated for ${email}`,
      user: {
        id: updatedAdmin.id,
        email: updatedAdmin.email,
        role: updatedAdmin.role
      }
    });

  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Update monthly summary amounts
app.put('/api/summary/monthly/:workerId', authenticateToken, async (req, res) => {
  try {
    const { workerId } = req.params;
    const { month, year, data } = req.body;

    // Validate required fields
    if (!month || !year || !data) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Ensure this action is performed by an authorized role
    if (!['Standard', 'Supervisor', 'Accountant', 'Director', 'RDM', 'RCM'].includes(req.user.role)) {
      return res.status(403).json({ error: 'Permission denied. Unauthorized role.' });
    }

    const formattedMonth = month.toString().padStart(2, '0');
    const startDate = `${year}-${formattedMonth}-01`;
    const endDate = new Date(year, parseInt(month), 0).toISOString().split('T')[0];

    // Get all entries for the worker in the specified month
    const { data: entries, error: findError } = await supabase
      .from('overtime_entries')
      .select('*')
      .eq('worker_id', workerId)
      .gte('date', startDate)
      .lte('date', endDate);

    if (findError) {
      console.error('Error finding entries:', findError);
      throw findError;
    }

    if (!entries || entries.length === 0) {
      return res.status(404).json({ error: 'No entries found for this period' });
    }

    // Calculate total hours for proportional distribution
    const totalCategoryAHours = entries.reduce((sum, entry) => sum + (entry.category_a_hours || 0), 0);
    const totalCategoryCHours = entries.reduce((sum, entry) => sum + (entry.category_c_hours || 0), 0);
    const totalTransportDays = entries.filter(entry => entry.transportation).length;

    // Update each entry proportionally
    const updatePromises = entries.map(async (entry) => {
      const categoryAHours = entry.category_a_hours || 0;
      const categoryCHours = entry.category_c_hours || 0;
      const hasTransport = entry.transportation;

      // Calculate proportional amounts
      const categoryAAmount = totalCategoryAHours > 0 
        ? (categoryAHours / totalCategoryAHours) * data.category_a_amount 
        : 0;
      
      const categoryCAmount = totalCategoryCHours > 0 
        ? (categoryCHours / totalCategoryCHours) * data.category_c_amount 
        : 0;
      
      const transportCost = totalTransportDays > 0 && hasTransport
        ? (1 / totalTransportDays) * data.transportation_cost 
        : 0;

      // Update the entry
      const { error: updateError } = await supabase
        .from('overtime_entries')
        .update({
          category_a_amount: categoryAAmount,
          category_c_amount: categoryCAmount,
          transportation_cost: transportCost,
          last_edited_by: req.user.id,
          last_edited_at: new Date().toISOString()
        })
        .eq('id', entry.id);

      if (updateError) {
        throw updateError;
      }
    });

    // Wait for all updates to complete
    await Promise.all(updatePromises);

    res.json({
      message: 'Successfully updated monthly amounts',
      workerId,
      month,
      year,
      totalEntries: entries.length
    });

  } catch (error) {
    console.error('Error updating monthly amounts:', error);
    res.status(500).json({ 
      error: error.message || 'An unexpected error occurred while updating amounts' 
    });
  }
});
