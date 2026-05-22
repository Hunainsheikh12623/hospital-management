import { NextResponse } from 'next/server';
import bcrypt from 'bcrypt';
import { pool } from '@/lib/db';

export async function POST(req: Request) {

  try {

    const body = await req.json();

    const {
      full_name,
      email,
      password,
      role_id
    } = body;

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user
    const query = `
      INSERT INTO users
      (full_name, email, password, role_id)
      VALUES ($1, $2, $3, $4)
      RETURNING *
    `;

    const values = [
      full_name,
      email,
      hashedPassword,
      role_id
    ];

    const result = await pool.query(query, values);

    return NextResponse.json({
      success: true,
      user: result.rows[0]
    });

  } catch (error) {

    console.error(error);

    return NextResponse.json(
      {
        success: false,
        message: 'Registration failed'
      },
      {
        status: 500
      }
    );
  }
}