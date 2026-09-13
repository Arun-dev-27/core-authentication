import { Body, Controller, HttpCode, Post } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { AppConfig } from '@config/config.module';
import { API_V1 } from '@common/constants/api-version.constants';
import { AuditService } from '@core/audit/audit.service';
import { assertClientCanAuthenticate, resolveCallback, resolveEmbedOrigin } from '@modules/clients/services/client-policy';
import { ClientRegistry } from '@modules/clients/services/client-registry.service';
import { TransactionService } from '../services/transaction.service';
import { CreateTransactionDto } from './dto/create-transaction.dto';

@ApiTags('auth')
@Controller({ path: 'auth/transaction', version: API_V1 })
export class TransactionsController {
  constructor(
    private readonly transactions: TransactionService,
    private readonly clients: ClientRegistry,
    private readonly config: AppConfig,
    private readonly audit: AuditService,
  ) {}

  /** Server-to-server: a BU backend may pre-register the transaction instead of generating the id itself. */
  @Post()
  @HttpCode(201)
  @ApiOperation({ summary: 'Pre-create a short-lived login transaction for a registered client' })
  async create(@Body() dto: CreateTransactionDto) {
    const display = dto.display ?? 'embed';
    const client = await this.clients.get(dto.client_id);
    assertClientCanAuthenticate(client, display);
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
    return {
      transaction_id: txn.transaction_id,
      expires_at: txn.expires_at,
      login_url: `${this.config.issuer}/embed/login?${params.toString()}`,
    };
  }
}
