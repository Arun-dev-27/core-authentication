import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AuthClient } from '../entities/auth/auth-client.entity';

/** `auth_clients` with its `auth_client_origins` and `auth_client_callbacks`. */
@Injectable()
export class AuthClientRepository {
  constructor(@InjectRepository(AuthClient) private readonly clients: Repository<AuthClient>) {}

  /** The client with its origins and callbacks, each in registration order. */
  findWithUris(clientId: string): Promise<AuthClient | null> {
    return this.clients.findOne({
      where: { clientId },
      relations: { origins: true, callbacks: true },
      order: { origins: { createdAt: 'ASC' }, callbacks: { createdAt: 'ASC' } },
    });
  }
}
