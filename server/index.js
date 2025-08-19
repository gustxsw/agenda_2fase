import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { pool } from "./db.js";
import { MercadoPagoConfig, Preference, Payment } from "mercadopago";
import create