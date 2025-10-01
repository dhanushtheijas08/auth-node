export class ApiError extends Error {
  statusCode: number;
  redirectRoute?: string;
  constructor(message: string, statusCode = 500, redirectRoute?: string) {
    super(message);
    this.statusCode = statusCode;
    this.redirectRoute = redirectRoute;

    Object.setPrototypeOf(this, ApiError.prototype);
  }
}
