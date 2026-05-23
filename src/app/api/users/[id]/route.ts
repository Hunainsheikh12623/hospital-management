import { NextRequest, NextResponse } from 'next/server';
import bcrypt from 'bcrypt';
import { pool } from '@/lib/db';
import { getTokenFromHeader, verifyJwt, ADMIN_ROLE_ID } from '@/lib/auth';

export async function PUT(
  req: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  try {
    const authorization = req.headers.get('authorization');
    const token = getTokenFromHeader(authorization || undefined);

    if (!token) {
      return NextResponse.json(
        { success: false, message: 'Authorization header required' },
        { status: 401 }
      );
    }

    let payload;
    try {
      payload = verifyJwt(token);
    } catch (error) {
      return NextResponse.json(
        { success: false, message: 'Invalid or expired token' },
        { status: 401 }
      );
    }

    if (payload.roleId !== ADMIN_ROLE_ID) {
      return NextResponse.json(
        { success: false, message: 'Only admin users can update users' },
        { status: 403 }
      );
    }

    const params = await context.params;
    const userId = Number(params.id);
    if (Number.isNaN(userId) || userId <= 0) {
      return NextResponse.json(
        { success: false, message: 'Invalid user ID' },
        { status: 400 }
      );
    }

    const body = await req.json();
    const { full_name, email, password, role_id } = body;

    const fields: string[] = [];
    const values: any[] = [];

    if (full_name) {
      values.push(full_name);
      fields.push(`full_name = $${values.length}`);
    }
    if (email) {
      values.push(email);
      fields.push(`email = $${values.length}`);
    }
    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      values.push(hashedPassword);
      fields.push(`password = $${values.length}`);
    }
    if (typeof role_id !== 'undefined') {
      values.push(role_id);
      fields.push(`role_id = $${values.length}`);
    }

    if (fields.length === 0) {
      return NextResponse.json(
        { success: false, message: 'No fields provided for update' },
        { status: 400 }
      );
    }

    const query = `UPDATE users SET ${fields.join(', ')} WHERE id = $${
      values.length + 1
    } RETURNING id, full_name, email, role_id`;
    values.push(userId);

    const result = await pool.query(query, values);

    if (result.rows.length === 0) {
      return NextResponse.json(
        { success: false, message: 'User not found' },
        { status: 404 }
      );
    }

    return NextResponse.json({ success: true, user: result.rows[0] });
  } catch (error) {
    console.error(error);
    return NextResponse.json(
      { success: false, message: 'User update failed' },
      { status: 500 }
    );
  }
}

export async function DELETE(
  req: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  try {
    const authorization = req.headers.get('authorization');
    const token = getTokenFromHeader(authorization || undefined);

    if (!token) {
      return NextResponse.json(
        { success: false, message: 'Authorization header required' },
        { status: 401 }
      );
    }

    let payload;
    try {
      payload = verifyJwt(token);
    } catch (error) {
      return NextResponse.json(
        { success: false, message: 'Invalid or expired token' },
        { status: 401 }
      );
    }

    if (payload.roleId !== ADMIN_ROLE_ID) {
      return NextResponse.json(
        { success: false, message: 'Only admin users can delete users' },
        { status: 403 }
      );
    }

    const params = await context.params;
    const userId = Number(params.id);
    if (Number.isNaN(userId) || userId <= 0) {
      return NextResponse.json(
        { success: false, message: 'Invalid user ID' },
        { status: 400 }
      );
    }

    const result = await pool.query(
      'DELETE FROM users WHERE id = $1 RETURNING id, full_name, email, role_id',
      [userId]
    );

    if (result.rows.length === 0) {
      return NextResponse.json(
        { success: false, message: 'User not found' },
        { status: 404 }
      );
    }

    return NextResponse.json({ success: true, user: result.rows[0] });
  } catch (error) {
    console.error(error);
    return NextResponse.json(
      { success: false, message: 'User delete failed' },
      { status: 500 }
    );
  }
}
