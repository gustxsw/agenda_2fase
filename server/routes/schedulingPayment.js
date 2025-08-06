const express = require('express');
const { MercadoPagoConfig, Preference } = require('mercadopago');
const { pool } = require('../db');
const { authenticate, authorize } = require('../middleware/auth');
const router = express.Router();

// Initialize MercadoPago
const client = new MercadoPagoConfig({
  accessToken: process.env.MP_ACCESS_TOKEN,
});

// Create scheduling subscription payment
router.post('/create-scheduling-subscription', authenticate, authorize(['professional']), async (req, res) => {
  try {
    console.log('🔄 Creating scheduling subscription for professional:', req.user.id);

    // Check if professional already has active scheduling subscription
    const existingSubscription = await pool.query(
      `SELECT * FROM professional_scheduling_subscriptions 
       WHERE professional_id = $1 AND status = 'active' AND expires_at > NOW()`,
      [req.user.id]
    );

    if (existingSubscription.rows.length > 0) {
      return res.status(400).json({ 
        message: 'Você já possui uma assinatura ativa do sistema de agendamentos' 
      });
    }

    const preference = new Preference(client);

    const preferenceData = {
      items: [
        {
          title: 'Sistema de Agendamentos - Quiro Ferreira',
          description: 'Assinatura mensal do sistema de agendamentos profissional',
          quantity: 1,
          unit_price: 49.90,
          currency_id: 'BRL',
        }
      ],
      payer: {
        name: req.user.name,
        email: req.user.email || `professional${req.user.id}@quiroferreira.com.br`,
      },
      back_urls: {
        success: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/professional/scheduling/payment-success`,
        failure: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/professional/scheduling/payment-failure`,
        pending: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/professional/scheduling/payment-pending`,
      },
      auto_return: 'approved',
      external_reference: `scheduling_${req.user.id}_${Date.now()}`,
      notification_url: `${process.env.API_URL || 'http://localhost:3001'}/api/scheduling-payment/webhook`,
      statement_descriptor: 'QUIRO FERREIRA AGENDA',
    };

    console.log('🔄 Creating MercadoPago preference:', preferenceData);

    const result = await preference.create({ body: preferenceData });

    console.log('✅ MercadoPago preference created:', result);

    // Store the payment intent in database
    await pool.query(
      `INSERT INTO professional_scheduling_payments 
       (professional_id, mp_preference_id, amount, status, external_reference)
       VALUES ($1, $2, $3, 'pending', $4)`,
      [req.user.id, result.id, 49.90, preferenceData.external_reference]
    );

    res.json({
      preference_id: result.id,
      init_point: result.init_point,
      sandbox_init_point: result.sandbox_init_point,
    });
  } catch (error) {
    console.error('❌ Error creating scheduling subscription:', error);
    res.status(500).json({ 
      message: 'Erro ao criar pagamento da assinatura',
      error: error.message 
    });
  }
});

// Handle MercadoPago webhook for scheduling payments
router.post('/webhook', async (req, res) => {
  try {
    console.log('🔔 Scheduling payment webhook received:', req.body);

    const { type, data } = req.body;

    if (type === 'payment') {
      const paymentId = data.id;
      
      // Here you would typically verify the payment with MercadoPago API
      // For now, we'll simulate payment approval
      
      // Find the payment record
      const paymentResult = await pool.query(
        `SELECT * FROM professional_scheduling_payments WHERE mp_payment_id = $1`,
        [paymentId]
      );

      if (paymentResult.rows.length > 0) {
        const payment = paymentResult.rows[0];
        
        // Update payment status
        await pool.query(
          `UPDATE professional_scheduling_payments 
           SET status = 'approved', updated_at = CURRENT_TIMESTAMP
           WHERE id = $1`,
          [payment.id]
        );

        // Create or update scheduling subscription
        const expiresAt = new Date();
        expiresAt.setMonth(expiresAt.getMonth() + 1); // 1 month from now

        await pool.query(
          `INSERT INTO professional_scheduling_subscriptions 
           (professional_id, status, expires_at, payment_id)
           VALUES ($1, 'active', $2, $3)
           ON CONFLICT (professional_id) 
           DO UPDATE SET 
             status = 'active',
             expires_at = $2,
             payment_id = $3,
             updated_at = CURRENT_TIMESTAMP`,
          [payment.professional_id, expiresAt, payment.id]
        );

        // Update professional schedule settings to enable scheduling
        await pool.query(
          `UPDATE professional_schedule_settings 
           SET has_scheduling_subscription = true
           WHERE professional_id = $1`,
          [payment.professional_id]
        );

        console.log('✅ Scheduling subscription activated for professional:', payment.professional_id);
      }
    }

    res.status(200).json({ received: true });
  } catch (error) {
    console.error('❌ Error processing scheduling payment webhook:', error);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

// Get professional's scheduling subscription status
router.get('/subscription-status', authenticate, authorize(['professional']), async (req, res) => {
  try {
    // 🔥 LIBERADO: Todos os profissionais têm acesso à agenda
    res.json({
      has_subscription: true,
      status: 'active',
      expires_at: null,
      created_at: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error fetching subscription status:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

module.exports = router;