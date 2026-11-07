import { mkdirSync,chmodSync } from 'node:fs';
import { dirname } from 'node:path';
import type { Config } from './config.ts';
import { fail } from './errors.ts';

export interface Result { rows:Record<string,any>[]; rowCount:number }
export interface Query { query(sql:string,params?:unknown[]):Promise<Result> }
export interface Database extends Query { transaction<T>(fn:(db:Query)=>Promise<T>):Promise<T>; close():Promise<void> }

export class SQLiteDatabase implements Database {
  connection:any; tail:Promise<void>=Promise.resolve();
  constructor(connection:any){this.connection=connection;}
  static async open(path:string){
    const {DatabaseSync}=await import('node:sqlite');
    if(path!==':memory:')mkdirSync(dirname(path),{recursive:true,mode:0o700});
    const db=new DatabaseSync(path);db.exec('PRAGMA foreign_keys=ON; PRAGMA secure_delete=ON; PRAGMA busy_timeout=5000;');
    if(path!==':memory:' && process.platform!=='win32')chmodSync(path,0o600);
    return new SQLiteDatabase(db);
  }
  async serial<T>(fn:()=>Promise<T>):Promise<T>{
    const previous=this.tail;let unlock!:()=>void;this.tail=new Promise<void>(resolve=>unlock=resolve);
    await previous;try{return await fn();}finally{unlock();}
  }
  raw(sql:string,params:unknown[]=[]):Promise<Result>{
    const values:unknown[]=[];
    const statement=this.connection.prepare(sql.replace(/\$(\d+)/g,(_,index)=>{values.push(params[Number(index)-1]);return '?';}));
    if(/^\s*(SELECT|PRAGMA|WITH)\b/i.test(sql) || /\bRETURNING\b/i.test(sql)){
      const rows=statement.all(...values);return Promise.resolve({rows,rowCount:rows.length});
    }
    const result=statement.run(...values);return Promise.resolve({rows:[],rowCount:Number(result.changes)});
  }
  query(sql:string,params:unknown[]=[]){return this.serial(()=>this.raw(sql,params));}
  transaction<T>(fn:(db:Query)=>Promise<T>):Promise<T>{
    return this.serial(async()=>{this.connection.exec('BEGIN IMMEDIATE');try{const result=await fn({query:(sql,params)=>this.raw(sql,params)});this.connection.exec('COMMIT');return result;}catch(error){this.connection.exec('ROLLBACK');throw error;}});
  }
  async close(){await this.serial(async()=>this.connection.close());}
}

export class PostgresDatabase implements Database {
  pool:any;
  constructor(pool:any){this.pool=pool;}
  static async open(url:string){
    const {Pool,types}=await import('pg');
    types.setTypeParser(20,Number); // Application timestamps/sequence values are bounded safe integers.
    return new PostgresDatabase(new Pool({connectionString:url,max:4,connectionTimeoutMillis:5000,idleTimeoutMillis:10000,statement_timeout:10000}));
  }
  async query(sql:string,params:unknown[]=[]):Promise<Result>{const r=await this.pool.query(sql,params);return {rows:r.rows,rowCount:r.rowCount??0};}
  async transaction<T>(fn:(db:Query)=>Promise<T>):Promise<T>{
    const client=await this.pool.connect();
    try{await client.query('BEGIN');const result=await fn({query:async(sql,params=[])=>{const r=await client.query(sql,params);return {rows:r.rows,rowCount:r.rowCount??0};}});await client.query('COMMIT');return result;}
    catch(error){await client.query('ROLLBACK');throw error;}finally{client.release();}
  }
  async close(){await this.pool.end();}
}
export async function openDatabase(config:Config):Promise<Database>{
  if(config.databaseUrl)return PostgresDatabase.open(config.databaseUrl);
  if(config.production)fail(503,'DATABASE_REQUIRED','Accounts require configured PostgreSQL in production.');
  return SQLiteDatabase.open(config.localDbPath);
}
