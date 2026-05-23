import {Pool} from "pg";

export const pool = new Pool({
    user: 'hunain',
    host: 'localhost',
    database: 'hospital_db',
    password: 'Hunain12',
    port: 5432,
});