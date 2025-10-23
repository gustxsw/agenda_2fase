@@ .. @@
   const formatDate = (dateString: string) => {
     if (!dateString) return "";
-    const date = new Date(dateString);
-    return date.toLocaleDateString("pt-BR");
+    // Convert from UTC (database) to Brazil local time for display
+    const utcDate = new Date(dateString);
+    const localDate = new Date(utcDate.getTime() - (3 * 60 * 60 * 1000));
+    return localDate.toLocaleDateString("pt-BR");
   };