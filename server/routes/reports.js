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
 // Get revenue report for admin
 router.get('/revenue', authenticate, authorize(['admin']), async (req, res) => {
   try {
@@ .. @@
         FROM consultations c
         JOIN users p ON c.professional_id = p.id
         LEFT JOIN services s ON c.service_id = s.id
-        WHERE p.roles @> '["professional"]'
+        WHERE p.roles::jsonb ? 'professional'
         AND c.date >= $1 AND c.date <= $2
         GROUP BY p.id, p.name, p.percentage
         ORDER BY total_revenue DESC`,