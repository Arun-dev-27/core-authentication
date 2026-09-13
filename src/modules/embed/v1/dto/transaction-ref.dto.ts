import { ApiProperty } from '@nestjs/swagger';
import { Matches } from 'class-validator';
import { CLIENT_ID_PATTERN, TRANSACTION_ID_PATTERN } from '@common/constants/validation.constants';

export class TransactionRefDto {
  @ApiProperty()
  @Matches(TRANSACTION_ID_PATTERN)
  transaction_id: string;

  @ApiProperty()
  @Matches(CLIENT_ID_PATTERN)
  client_id: string;
}
