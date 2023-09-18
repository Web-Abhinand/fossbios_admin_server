const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const Admin = require('./adminModel');
const User = require('./userModel');


// Signup endpoint for admin
router.post('/admin-signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Check if the admin already exists
    const existingAdmin = await Admin.findOne({ email });
    if (existingAdmin) {
      return res.status(400).json({ message: 'Admin already exists' });
    }

    // Hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create a new admin user
    const newAdmin = await Admin.create({
      name,
      email,
      password: hashedPassword,
    });

    res.status(200).json({ message: 'Admin registered successfully' });
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: 'Error registering admin' });
  }
});

router.post('/admin-login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if the admin exists
    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(400).json({ message: 'Admin not found' });
    }

    // Check if the password is correct
    const isPasswordValid = await bcrypt.compare(password, admin.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: 'Invalid password' });
    }

    // Check if the admin is approved
    if (!admin.approved) {
      return res.status(401).json({ message: 'Admin not approved' });
    }

    // Check if the admin is a super admin
    const isAdminSuperAdmin = admin.email === 'superadmin@gmail.com';

    // Create the payload for the JWT
    const payload = {
      email: admin.email,
      role: admin.role,
      isAdminSuperAdmin, // Add the isAdminSuperAdmin flag to the payload
    };

    // Sign the token with your secret key
    const secretKey = 'secret_key';
    const token = jwt.sign(payload, secretKey, { expiresIn: '1h' });

    res.status(200).json({ token });
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: 'Error logging in' });
  }
});

// Middleware to check if the request is coming from an admin user
const isAdmin = async (req, res, next) => {
  try {
    const secretKey = 'secret_key';
    const token = req.headers.authorization;
    if (!token) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    const tokenWithoutBearer = token.split(' ')[1]; // Remove "Bearer" prefix
    const decodedToken = jwt.verify(tokenWithoutBearer, secretKey);
    const adminEmail = decodedToken.email;
    console.log(adminEmail, 'adminEmail')
    const admin = await Admin.findOne({ email: adminEmail });
    if (!admin) {
      return res.status(403).json({ message: 'Permission denied' });
    }
    req.admin = admin; // Pass the admin object to the request for further use
    next();
  } catch (err) {
    console.log(err);
    return res.status(500).json({ message: 'Error authenticating admin' });
  }
};

router.get('/leads', isAdmin, async (req, res) => {
  try {
    const leads = await User.find({ role: 'lead' });
    res.status(200).json(leads);
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: 'Error retrieving leads' });
  }
});

router.get('/admins', isAdmin, async (req, res) => {
  try {
    if (req.admin.email === 'superadmin@gmail.com') {
      const admins = await Admin.find({ role: 'admin' });
      res.status(200).json(admins);
    } else {
      return res.status(403).json({ message: 'Permission denied' });
    }
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: 'Error retrieving admins' });
  }
});

router.get('/allusers', isAdmin, async (req, res) => {
  try {
    const users = await User.find(); // Remove the role filter
    res.status(200).json(users);
    console.log(users);
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: 'Error retrieving users' });
  }
});

router.put('/approve-admin/:adminId', isAdmin, async (req, res) => {
  try {
    const { adminId } = req.params;
    const admin = await Admin.findById(adminId);
    
    if (!admin) {
      return res.status(404).json({ message: 'Admin not found' });
    }

    admin.approved = true; // Approve the admin
    await admin.save();
    
    return res.status(200).json({ message: 'Admin approved' });
  } catch (err) {
    return res.status(500).json({ message: 'Error approving admin' });
  }
});

router.put('/approve-lead/:leadId', isAdmin, async (req, res) => {
  try {
    const { leadId } = req.params;
    const lead = await User.findById(leadId);
    if(!lead){
      return res.status(404).json({ message: 'Lead not found' });
    }
    lead.approved = true; // Approve the lead
    await lead.save();
    return res.status(200).json({ message: 'Lead approved' });
  } catch (err) {
    return res.status(500).json({ message: 'Error approving lead' });
  }
});

router.put('/approve-leave/:user_id/:index',isAdmin, async (req, res) => {
  try {
    const { user_id } = req.params;
    const { index } = req.params;
    const user = await User.findById(user_id);
    if(!user){
      return res.status(404).json({ message: 'User not found' });
    }
    user.leaveRequests[index].leaveApproved = true; // Approve the leave
    await user.save();
    return res.status(200).json({ message: 'Leave approved' });
    
  } catch (err) {
    return res.status(500).json({ message: 'Error approving leave' });
  }
});

module.exports = router;
