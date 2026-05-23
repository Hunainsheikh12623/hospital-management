import { NextRequest, NextResponse } from 'next/server';
import { pool } from '@/lib/db';
import { getTokenFromHeader, verifyJwt, ADMIN_ROLE_ID } from '@/lib/auth';

export async function GET(req: NextRequest) {
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
        { success: false, message: 'Only admin users can view users' },
        { status: 403 }
      );
    }

    const result = await pool.query(
      'SELECT id, full_name, email, role_id FROM users WHERE role_id <> $1 ORDER BY id',
      [ADMIN_ROLE_ID]
    );

    return NextResponse.json({ success: true, users: result.rows });
  } catch (error) {
    console.error(error);
    return NextResponse.json(
      { success: false, message: 'Failed to fetch users' },
      { status: 500 }
    );
  }
}
