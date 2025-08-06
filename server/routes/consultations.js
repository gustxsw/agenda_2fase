@@ .. @@
 import express from 'express';
 import { pool } from '../db.js';
 import { authenticate, authorize } from '../middleware/auth.js';
 
 const router = express.Router();
 
+// Helper function to safely parse roles
+const parseRoles = (roles) => {
+  if (!roles) return [];
+  if (Array.isArray(roles)) return roles;
+  if (typeof roles === 'string') {
+    try {
+      return JSON.parse(roles);
+    } catch (e) {
+      // If it's not valid JSON, treat as single role
+      return roles.includes(',') ? roles.split(',').map(r => r.trim()) : [roles];
+    }
+  }
+  return [roles];
+};
+
 // Get consultations for current user
 router.get('/', authenticate, async (req, res) => {
   try {
     let query;
     let params;
     
-    if (req.user.currentRole === 'client') {
+    const userRoles = parseRoles(req.user.roles);
+    
+    if (req.user.currentRole === 'client' || userRoles.includes('client')) {
       // For clients, get their consultations and their dependents' consultations