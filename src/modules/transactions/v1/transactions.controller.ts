import { Body, Controller, Get, HttpCode, Param, Post, Query } from '@nestjs/common';
import { ApiOperation, ApiQuery, ApiTags } from '@nestjs/swagger';
import { AppConfig } from '@config/config.module';
import { API_V1 } from '@common/constants/api-version.constants';
import { CLIENT_ID_PATTERN } from '@common/constants/validation.constants';
import { Errors } from '@common/errors/domain-error';
import { AuditService } from '@core/audit/audit.service';
import { assertClientCanAuthenticate, resolveCallback, resolveEmbedOrigin } from '@modules/clients/services/client-policy';
import { ClientRegistry } from '@modules/clients/services/client-registry.service';
import { TransactionService } from '../services/transaction.service';
import { CreateTransactionDto } from './dto/create-transaction.dto';

export const CSRF_HEADER = 'x-csrf-token';

@ApiTags('auth')
@Controller({ path: 'auth/transaction', version: API_V1 })
export class TransactionsController {
  constructor(
    private readonly transactions: TransactionService,
    private readonly clients: ClientRegistry,
    private readonly config: AppConfig,
    private readonly audit: AuditService,
  ) {}

  /**
   * Server-to-server: a BU backend (or any API client) creates the transaction. Everything is derived from the client's
   * current configuration in the Authorization service, read fresh, so an origin added or removed there applies here at once.
   */
  @Post()
  @HttpCode(201)
  @ApiOperation({ summary: 'Create a login transaction for a registered client: login_url, bound origin, expiry and (configurable) CSRF token' })
  async create(@Body() dto: CreateTransactionDto) {
    const display = dto.display ?? 'embed';
    const client = await this.clients.getFresh(dto.client_id);
    assertClientCanAuthenticate(client, display);
    // A client may register several origins: the request selects one exactly (defaults only when exactly one is registered).
    const embedOrigin = display === 'embed' ? resolveEmbedOrigin(client, dto.origin) : null;
    const callback = resolveCallback(client, dto.redirect_uri);

    const txn = await this.transactions.create({
      transaction_id: TransactionService.generateId(),
      client_id: client.client_id,
      state: dto.state,
      display,
      embed_origin: embedOrigin,
      callback_uri: callback,
    });
    await this.audit.record({ eventType: 'TRANSACTION_CREATED', outcome: 'INFO', clientId: client.client_id, metadata: { display, api: true } });

    const params = new URLSearchParams({ client_id: client.client_id, transaction_id: txn.transaction_id, state: dto.state, display });
    if (embedOrigin) params.set('origin', embedOrigin);
    // The login page resolves the callback from redirect_uri again; pass it so both resolve to the same transaction.
    if (dto.redirect_uri) params.set('redirect_uri', callback);

    return {
      transaction_id: txn.transaction_id,
      client_id: client.client_id,
      display,
      state: txn.state,
      status: txn.status,
      target_origin: embedOrigin,
      callback_uri: display === 'page' ? callback : null,
      expires_at: txn.expires_at,
      expires_in: this.config.env.TRANSACTION_TTL_SECONDS,
      login_url: `${this.config.issuer}/embed/login?${params.toString()}`,
      ...(this.config.transactionApiReturnsCsrf ? { csrf: txn.csrf, csrf_header: CSRF_HEADER, required_origin: this.config.issuer } : {}),
    };
  }

  /** Status of a transaction for its own client. Never returns the CSRF token or the state. */
  @Get(':transactionId')
  @ApiOperation({ summary: 'Transaction status (PENDING or COMPLETED), bound origin and remaining lifetime' })
  @ApiQuery({ name: 'client_id', required: true })
  async status(@Param('transactionId') transactionId: string, @Query('client_id') clientId?: string) {
    if (typeof clientId !== 'string' || !CLIENT_ID_PATTERN.test(clientId)) throw Errors.invalidRequest('client_id is required');
    const txn = await this.transactions.get(transactionId);
    if (!txn || txn.client_id !== clientId) throw Errors.transactionInvalid();
    return {
      transaction_id: txn.transaction_id,
      client_id: txn.client_id,
      display: txn.display,
      status: txn.status,
      target_origin: txn.embed_origin,
      expires_at: txn.expires_at,
      expires_in: await this.transactions.remainingSeconds(txn.transaction_id),
    };
  }
}
