SELECT
  `usrsum`.`user` AS `USER`,
  `usrsum`.`total_connections` AS `TOTAL_CONNECTIONS`
FROM
  `sys`.`user_summary` AS `usrsum`
ORDER BY
  `usrsum`.`total_connections` DESC
LIMIT 5;
