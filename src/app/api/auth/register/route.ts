import { NextResponse } from 'next/server';
import bcrypt from 'bcrypt';
import { pool } from '@/lib/db';
import { getTokenFromHeader, verifyJwt, ADMIN_ROLE_ID } from '@/lib/auth';

export async function POST(req: Request) {
  try {
    const authorization = req.headers.get('authorization');
    const token = getTokenFromHeader(authorization || undefined);

    if (!token) {
      return NextResponse.json(
        {
          success: false,
          message: 'Authorization header required',
        },
        {
          status: 401,
        }
      );
    }

    let payload;
    try {
      payload = verifyJwt(token);
    } catch (error) {
      return NextResponse.json(
        {
          success: false,
          message: 'Invalid or expired token',
        },
        {
          status: 401,
        }
      );
    }

    if (payload.roleId !== ADMIN_ROLE_ID) {
      return NextResponse.json(
        {
          success: false,
          message: 'Only admin users can register new users',
        },
        {
          status: 403,
        }
      );
    }

    const body = await req.json();
    const { full_name, email, password, role_id } = body;

    if (!full_name || !email || !password || !role_id) {
      return NextResponse.json(
        {
          success: false,
          message: 'Missing registration fields',
        },
        {
          status: 400,
        }
      );
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const query = `
      INSERT INTO users
      (full_name, email, password, role_id)
      VALUES ($1, $2, $3, $4)
      RETURNING *
    `;

    const values = [full_name, email, hashedPassword, role_id];
    const result = await pool.query(query, values);

    return NextResponse.json({
      success: true,
      user: result.rows[0],
    });
  } catch (error) {
    console.error(error);
    return NextResponse.json(
      {
        success: false,
        message: 'Registration failed',
      },
      {
        status: 500,
      }
    );
  }
}
