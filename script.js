const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const path = require('path');

// Load environment variables
dotenv.config();

// Import routes
const appointmentRoutes = require('./routes/appointments');
const contactRoutes = require('./routes/contact');
const adminRoutes = require('./routes/admin');

const app = express();

// Database connection
require('./config/database')();

// Middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(morgan('dev'));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// Routes
app.use('/api/appointments', appointmentRoutes);
app.use('/api/contact', contactRoutes);
app.use('/api/admin', adminRoutes);

// Serve frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    success: false, 
    message: 'Something went wrong!',
    error: process.env.NODE_ENV === 'development' ? err.message : {}
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Route not found' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log(`MongoDB Connected: ${conn.connection.host}`);
  } catch (error) {
    console.error('Database connection error:', error);
    process.exit(1);
  }
};

module.exports = connectDB;
const mongoose = require('mongoose');

const appointmentSchema = new mongoose.Schema({
  patientName: {
    type: String,
    required: [true, 'Patient name is required'],
    trim: true,
    minlength: [2, 'Name must be at least 2 characters'],
    maxlength: [50, 'Name cannot exceed 50 characters']
  },
  patientEmail: {
    type: String,
    required: [true, 'Email is required'],
    trim: true,
    lowercase: true,
    match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
  },
  patientPhone: {
    type: String,
    required: [true, 'Phone number is required'],
    match: [/^[0-9]{10}$/, 'Please enter a valid 10-digit phone number']
  },
  patientAge: {
    type: Number,
    required: [true, 'Age is required'],
    min: [0, 'Age cannot be negative'],
    max: [150, 'Please enter valid age']
  },
  gender: {
    type: String,
    required: true,
    enum: ['Male', 'Female', 'Other']
  },
  department: {
    type: String,
    required: [true, 'Department is required'],
    enum: ['Cardiology', 'Neurology', 'Maternity', 'Radiology', 'General Medicine', 'Pediatrics', 'Orthopedics']
  },
  doctor: {
    type: String,
    required: [true, 'Doctor preference is required']
  },
  appointmentDate: {
    type: Date,
    required: [true, 'Appointment date is required']
  },
  appointmentTime: {
    type: String,
    required: [true, 'Appointment time is required']
  },
  symptoms: {
    type: String,
    required: [true, 'Please describe your symptoms'],
    maxlength: [500, 'Symptoms cannot exceed 500 characters']
  },
  isFirstVisit: {
    type: Boolean,
    default: true
  },
  status: {
    type: String,
    enum: ['pending', 'confirmed', 'cancelled', 'completed'],
    default: 'pending'
  },
  appointmentId: {
    type: String,
    unique: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Generate unique appointment ID before saving
appointmentSchema.pre('save', async function(next) {
  if (!this.appointmentId) {
    const date = new Date();
    const year = date.getFullYear().toString().slice(-2);
    const month = (date.getMonth() + 1).toString().padStart(2, '0');
    const count = await this.constructor.countDocuments();
    this.appointmentId = `APT${year}${month}${(count + 1).toString().padStart(4, '0')}`;
  }
  next();
});

module.exports = mongoose.model('Appointment', appointmentSchema);
const mongoose = require('mongoose');

const contactSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Name is required'],
    trim: true,
    minlength: [2, 'Name must be at least 2 characters'],
    maxlength: [50, 'Name cannot exceed 50 characters']
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    trim: true,
    lowercase: true,
    match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
  },
  phone: {
    type: String,
    required: [true, 'Phone number is required'],
    match: [/^[0-9]{10}$/, 'Please enter a valid 10-digit phone number']
  },
  subject: {
    type: String,
    required: [true, 'Subject is required'],
    enum: ['General Inquiry', 'Appointment', 'Emergency', 'Feedback', 'Complaint', 'Others']
  },
  message: {
    type: String,
    required: [true, 'Message is required'],
    maxlength: [1000, 'Message cannot exceed 1000 characters']
  },
  status: {
    type: String,
    enum: ['new', 'read', 'replied'],
    default: 'new'
  },
  ticketId: {
    type: String,
    unique: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Generate unique ticket ID before saving
contactSchema.pre('save', async function(next) {
  if (!this.ticketId) {
    const date = new Date();
    const year = date.getFullYear().toString().slice(-2);
    const month = (date.getMonth() + 1).toString().padStart(2, '0');
    const count = await this.constructor.countDocuments();
    this.ticketId = `TKT${year}${month}${(count + 1).toString().padStart(4, '0')}`;
  }
  next();
});

module.exports = mongoose.model('Contact', contactSchema);
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const adminSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true
  },
  password: {
    type: String,
    required: true
  },
  role: {
    type: String,
    enum: ['superadmin', 'admin', 'moderator'],
    default: 'admin'
  },
  lastLogin: {
    type: Date
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Hash password before saving
adminSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Compare password method
adminSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('Admin', adminSchema);
const Appointment = require('../models/Appointment');
const { validationResult } = require('express-validator');
const nodemailer = require('nodemailer');

// Create appointment
exports.createAppointment = async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        success: false, 
        errors: errors.array() 
      });
    }

    const appointment = new Appointment(req.body);
    await appointment.save();

    // Send confirmation email
    await sendConfirmationEmail(appointment);

    res.status(201).json({
      success: true,
      message: 'Appointment booked successfully',
      data: {
        appointmentId: appointment.appointmentId,
        patientName: appointment.patientName,
        appointmentDate: appointment.appointmentDate,
        appointmentTime: appointment.appointmentTime
      }
    });
  } catch (error) {
    console.error('Appointment creation error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to book appointment',
      error: error.message 
    });
  }
};

// Get appointment by ID
exports.getAppointment = async (req, res) => {
  try {
    const appointment = await Appointment.findOne({ 
      appointmentId: req.params.id 
    });
    
    if (!appointment) {
      return res.status(404).json({ 
        success: false, 
        message: 'Appointment not found' 
      });
    }

    res.json({
      success: true,
      data: appointment
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching appointment' 
    });
  }
};

// Cancel appointment
exports.cancelAppointment = async (req, res) => {
  try {
    const appointment = await Appointment.findOneAndUpdate(
      { appointmentId: req.params.id },
      { status: 'cancelled' },
      { new: true }
    );

    if (!appointment) {
      return res.status(404).json({ 
        success: false, 
        message: 'Appointment not found' 
      });
    }

    // Send cancellation email
    await sendCancellationEmail(appointment);

    res.json({
      success: true,
      message: 'Appointment cancelled successfully',
      data: appointment
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Error cancelling appointment' 
    });
  }
};

// Get available slots
exports.getAvailableSlots = async (req, res) => {
  try {
    const { date, department } = req.query;
    
    // Define time slots
    const timeSlots = [
      '09:00 AM', '09:30 AM', '10:00 AM', '10:30 AM',
      '11:00 AM', '11:30 AM', '12:00 PM', '02:00 PM',
      '02:30 PM', '03:00 PM', '03:30 PM', '04:00 PM',
      '04:30 PM', '05:00 PM'
    ];

    // Find booked appointments for the given date and department
    const bookedAppointments = await Appointment.find({
      appointmentDate: new Date(date),
      department: department,
      status: { $in: ['pending', 'confirmed'] }
    });

    const bookedSlots = bookedAppointments.map(apt => apt.appointmentTime);
    
    // Filter available slots
    const availableSlots = timeSlots.filter(slot => !bookedSlots.includes(slot));

    res.json({
      success: true,
      data: {
        date,
        department,
        availableSlots,
        totalSlots: timeSlots.length,
        bookedSlots: bookedSlots.length
      }
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching available slots' 
    });
  }
};

// Email sending functions
async function sendConfirmationEmail(appointment) {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: appointment.patientEmail,
    subject: `Appointment Confirmation - Prime Hospital (ID: ${appointment.appointmentId})`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #0b2b44;">Prime Hospital - Appointment Confirmation</h2>
        <p>Dear ${appointment.patientName},</p>
        <p>Your appointment has been successfully booked with the following details:</p>
        
        <div style="background-color: #f4fbfe; padding: 20px; border-radius: 10px; margin: 20px 0;">
          <p><strong>Appointment ID:</strong> ${appointment.appointmentId}</p>
          <p><strong>Department:</strong> ${appointment.department}</p>
          <p><strong>Doctor:</strong> ${appointment.doctor}</p>
          <p><strong>Date:</strong> ${new Date(appointment.appointmentDate).toLocaleDateString()}</p>
          <p><strong>Time:</strong> ${appointment.appointmentTime}</p>
          <p><strong>Location:</strong> CX7Q+8WF, Khandsa Rd, Sector 36, Haryana 122004</p>
        </div>
        
        <p><strong>Important Instructions:</strong></p>
        <ul>
          <li>Please arrive 15 minutes before your appointment time</li>
          <li>Bring your previous medical records if any</li>
          <li>Carry a valid ID proof</li>
        </ul>
        
        <p>To cancel or reschedule, visit our website or contact us at +91 124 488 2200</p>
        
        <hr style="border: 1px solid #d9f2f0; margin: 20px 0;">
        <p style="color: #666; font-size: 12px;">Prime Hospital, Khandsa Road, Sector 36, Mohammadpur Jharsa, Haryana 122004</p>
      </div>
    `
  };

  await transporter.sendMail(mailOptions);
}

async function sendCancellationEmail(appointment) {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: appointment.patientEmail,
    subject: `Appointment Cancellation - Prime Hospital (ID: ${appointment.appointmentId})`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #0b2b44;">Prime Hospital - Appointment Cancellation</h2>
        <p>Dear ${appointment.patientName},</p>
        <p>Your appointment has been cancelled successfully.</p>
        
        <div style="background-color: #f4fbfe; padding: 20px; border-radius: 10px; margin: 20px 0;">
          <p><strong>Cancelled Appointment ID:</strong> ${appointment.appointmentId}</p>
          <p><strong>Department:</strong> ${appointment.department}</p>
          <p><strong>Date:</strong> ${new Date(appointment.appointmentDate).toLocaleDateString()}</p>
          <p><strong>Time:</strong> ${appointment.appointmentTime}</p>
        </div>
        
        <p>If you wish to book a new appointment, please visit our website or call us at +91 124 488 2200.</p>
        
        <hr style="border: 1px solid #d9f2f0; margin: 20px 0;">
        <p style="color: #666; font-size: 12px;">Prime Hospital, Khandsa Road, Sector 36, Mohammadpur Jharsa, Haryana 122004</p>
      </div>
    `
  };

  await transporter.sendMail(mailOptions);
}
const Contact = require('../models/Contact');
const { validationResult } = require('express-validator');
const nodemailer = require('nodemailer');

// Submit contact form
exports.submitContact = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        success: false, 
        errors: errors.array() 
      });
    }

    const contact = new Contact(req.body);
    await contact.save();

    // Send acknowledgment email
    await sendAcknowledgmentEmail(contact);

    // Notify admin
    await notifyAdmin(contact);

    res.status(201).json({
      success: true,
      message: 'Your message has been sent successfully',
      data: {
        ticketId: contact.ticketId,
        name: contact.name,
        subject: contact.subject
      }
    });
  } catch (error) {
    console.error('Contact form error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to send message',
      error: error.message 
    });
  }
};

// Get contact by ticket ID
exports.getContactByTicket = async (req, res) => {
  try {
    const contact = await Contact.findOne({ 
      ticketId: req.params.ticketId 
    });
    
    if (!contact) {
      return res.status(404).json({ 
        success: false, 
        message: 'Ticket not found' 
      });
    }

    res.json({
      success: true,
      data: contact
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching ticket' 
    });
  }
};

// Email functions
async function sendAcknowledgmentEmail(contact) {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: contact.email,
    subject: `We've received your message - Prime Hospital (Ticket: ${contact.ticketId})`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #0b2b44;">Thank you for contacting Prime Hospital</h2>
        <p>Dear ${contact.name},</p>
        <p>We have received your inquiry and our team will get back to you within 24 hours.</p>
        
        <div style="background-color: #f4fbfe; padding: 20px; border-radius: 10px; margin: 20px 0;">
          <p><strong>Ticket ID:</strong> ${contact.ticketId}</p>
          <p><strong>Subject:</strong> ${contact.subject}</p>
          <p><strong>Message:</strong> ${contact.message}</p>
        </div>
        
        <p>For immediate assistance during an emergency, please call our 24x7 helpline: <strong>108</strong></p>
        
        <hr style="border: 1px solid #d9f2f0; margin: 20px 0;">
        <p style="color: #666; font-size: 12px;">Prime Hospital, Khandsa Road, Sector 36, Mohammadpur Jharsa, Haryana 122004</p>
      </div>
    `
  };

  await transporter.sendMail(mailOptions);
}

async function notifyAdmin(contact) {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: process.env.ADMIN_EMAIL,
    subject: `New Contact Form Submission - Ticket ${contact.ticketId}`,
    html: `
      <div style="font-family: Arial, sans-serif;">
        <h3>New Contact Form Submission</h3>
        <p><strong>Ticket ID:</strong> ${contact.ticketId}</p>
        <p><strong>Name:</strong> ${contact.name}</p>
        <p><strong>Email:</strong> ${contact.email}</p>
        <p><strong>Phone:</strong> ${contact.phone}</p>
        <p><strong>Subject:</strong> ${contact.subject}</p>
        <p><strong>Message:</strong> ${contact.message}</p>
        <p><strong>Received:</strong> ${new Date(contact.createdAt).toLocaleString()}</p>
      </div>
    `
  };

  await transporter.sendMail(mailOptions);
}
const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const appointmentController = require('../controllers/appointmentController');

// Validation rules
const appointmentValidation = [
  body('patientName').trim().isLength({ min: 2 }).withMessage('Name must be at least 2 characters'),
  body('patientEmail').isEmail().withMessage('Valid email required'),
  body('patientPhone').matches(/^[0-9]{10}$/).withMessage('Valid 10-digit phone required'),
  body('patientAge').isInt({ min: 0, max: 150 }).withMessage('Valid age required'),
  body('gender').isIn(['Male', 'Female', 'Other']).withMessage('Valid gender required'),
  body('department').notEmpty().withMessage('Department required'),
  body('doctor').notEmpty().withMessage('Doctor preference required'),
  body('appointmentDate').isISO8601().withMessage('Valid date required'),
  body('appointmentTime').notEmpty().withMessage('Time required'),
  body('symptoms').isLength({ max: 500 }).withMessage('Symptoms too long')
];

// Routes
router.post('/', appointmentValidation, appointmentController.createAppointment);
router.get('/slots', appointmentController.getAvailableSlots);
router.get('/:id', appointmentController.getAppointment);
router.put('/:id/cancel', appointmentController.cancelAppointment);

module.exports = router;
const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const contactController = require('../controllers/contactController');

const contactValidation = [
  body('name').trim().isLength({ min: 2 }).withMessage('Name must be at least 2 characters'),
  body('email').isEmail().withMessage('Valid email required'),
  body('phone').matches(/^[0-9]{10}$/).withMessage('Valid 10-digit phone required'),
  body('subject').isIn(['General Inquiry', 'Appointment', 'Emergency', 'Feedback', 'Complaint', 'Others']),
  body('message').isLength({ max: 1000 }).withMessage('Message too long')
];

router.post('/', contactValidation, contactController.submitContact);
router.get('/:ticketId', contactController.getContactByTicket);

module.exports = router;
const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const contactController = require('../controllers/contactController');

const contactValidation = [
  body('name').trim().isLength({ min: 2 }).withMessage('Name must be at least 2 characters'),
  body('email').isEmail().withMessage('Valid email required'),
  body('phone').matches(/^[0-9]{10}$/).withMessage('Valid 10-digit phone required'),
  body('subject').isIn(['General Inquiry', 'Appointment', 'Emergency', 'Feedback', 'Complaint', 'Others']),
  body('message').isLength({ max: 1000 }).withMessage('Message too long')
];

router.post('/', contactValidation, contactController.submitContact);
router.get('/:ticketId', contactController.getContactByTicket);

module.exports = router;
const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const Admin = require('../models/Admin');
const Appointment = require('../models/Appointment');
const Contact = require('../models/Contact');
const auth = require('../middleware/auth');

// Admin login
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Find admin
    const admin = await Admin.findOne({ username });
    if (!admin) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    // Check password
    const isMatch = await admin.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    // Update last login
    admin.lastLogin = new Date();
    await admin.save();

    // Create token
    const token = jwt.sign(
      { id: admin._id, username: admin.username, role: admin.role },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      success: true,
      message: 'Login successful',
      token,
      admin: {
        username: admin.username,
        email: admin.email,
        role: admin.role
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Login failed' });
  }
});

// Get dashboard stats (protected)
router.get('/dashboard/stats', auth, async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const stats = {
      totalAppointments: await Appointment.countDocuments(),
      todayAppointments: await Appointment.countDocuments({
        appointmentDate: { $gte: today }
      }),
      pendingAppointments: await Appointment.countDocuments({ status: 'pending' }),
      totalContacts: await Contact.countDocuments(),
      newContacts: await Contact.countDocuments({ status: 'new' }),
      recentAppointments: await Appointment.find()
        .sort({ createdAt: -1 })
        .limit(5)
        .select('patientName department appointmentDate status appointmentId'),
      recentContacts: await Contact.find()
        .sort({ createdAt: -1 })
        .limit(5)
        .select('name subject status ticketId')
    };

    res.json({ success: true, data: stats });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Error fetching stats' });
  }
});

// Get all appointments (protected)
router.get('/appointments', auth, async (req, res) => {
  try {
    const { page = 1, limit = 10, status, department } = req.query;
    const query = {};
    
    if (status) query.status = status;
    if (department) query.department = department;

    const appointments = await Appointment.find(query)
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await Appointment.countDocuments(query);

    res.json({
      success: true,
      data: appointments,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Error fetching appointments' });
  }
});

// Update appointment status (protected)
router.put('/appointments/:id', auth, async (req, res) => {
  try {
    const { status } = req.body;
    const appointment = await Appointment.findOneAndUpdate(
      { appointmentId: req.params.id },
      { status },
      { new: true }
    );

    if (!appointment) {
      return res.status(404).json({ success: false, message: 'Appointment not found' });
    }

    res.json({ success: true, data: appointment });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Error updating appointment' });
  }
});

// Get all contacts (protected)
router.get('/contacts', auth, async (req, res) => {
  try {
    const { page = 1, limit = 10, status, subject } = req.query;
    const query = {};
    
    if (status) query.status = status;
    if (subject) query.subject = subject;

    const contacts = await Contact.find(query)
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await Contact.countDocuments(query);

    res.json({
      success: true,
      data: contacts,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Error fetching contacts' });
  }
});

// Update contact status (protected)
router.put('/contacts/:id', auth, async (req, res) => {
  try {
    const { status } = req.body;
    const contact = await Contact.findOneAndUpdate(
      { ticketId: req.params.id },
      { status },
      { new: true }
    );

    if (!contact) {
      return res.status(404).json({ success: false, message: 'Contact not found' });
    }

    res.json({ success: true, data: contact });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Error updating contact' });
  }
});

module.exports = router;
const jwt = require('jsonwebtoken');

module.exports = function(req, res, next) {
  // Get token from header
  const token = req.header('x-auth-token');

  // Check if no token
  if (!token) {
    return res.status(401).json({ success: false, message: 'No token, authorization denied' });
  }

  // Verify token
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.admin = decoded;
    next();
  } catch (err) {
    res.status(401).json({ success: false, message: 'Token is not valid' });
  }
};
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const Admin = require('./models/Admin');

dotenv.config();

mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const createInitialAdmin = async () => {
  try {
    // Check if admin already exists
    const adminExists = await Admin.findOne({ username: 'admin' });
    
    if (!adminExists) {
      const admin = new Admin({
        username: 'admin',
        email: 'admin@primehospital.in',
        password: 'Admin@123', // Change this!
        role: 'superadmin'
      });

      await admin.save();
      console.log('Initial admin created successfully');
      console.log('Username: admin');
      console.log('Password: Admin@123');
      console.log('Please change the password after first login!');
    } else {
      console.log('Admin already exists');
    }
  } catch (error) {
    console.error('Error creating admin:', error);
  } finally {
    mongoose.disconnect();
  }
};

createInitialAdmin();
