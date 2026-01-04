// 只定义本项目需要的最小 Redis 接口，避免类型泛型/模块扩展带来的 TS 类型不兼容。
export type RedisClientLike = {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, opts?: any): Promise<any>;
  del(key: string): Promise<any>;
  eval(script: string, opts: { keys: string[]; arguments: string[] }): Promise<unknown>;
};

