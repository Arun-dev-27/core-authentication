import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsIn, IsOptional, IsUUID, Matches, ValidateIf } from 'class-validator';
import { TRANSACTION_ID_PATTERN } from '@common/constants/validation.constants';

export class SelectScopeDto {
  @ApiProperty({ description: 'Portal transaction from the login page (CSRF binding)' })
  @Matches(TRANSACTION_ID_PATTERN)
  transaction_id: string;

  @ApiProperty({ example: '6b1f3c2e-8a3d-4a5b-9c1e-2d3f4a5b6c7d' })
  @IsUUID()
  role_id: string;

  @ApiProperty({ enum: ['CORE', 'BUSINESS_UNIT', 'UTILITY'], example: 'UTILITY' })
  @IsIn(['CORE', 'BUSINESS_UNIT', 'UTILITY'])
  scope_type: 'CORE' | 'BUSINESS_UNIT' | 'UTILITY';

  @ApiPropertyOptional({ nullable: true, description: 'NULL for CORE, else bu_id or utility_id' })
  @ValidateIf((o: SelectScopeDto) => o.scope_type !== 'CORE' || (o.scope_id !== undefined && o.scope_id !== null))
  @IsUUID()
  scope_id?: string | null;

  @ApiPropertyOptional({
    enum: ['authorization', 'identity'],
    default: 'authorization',
    description: 'authorization = Core Identity Authorization APIs (e.g. GET /me/permissions); identity = this service (force federation logout)',
  })
  @IsOptional()
  @IsIn(['authorization', 'identity'])
  audience?: 'authorization' | 'identity';
}
