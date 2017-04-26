SELECT
  `usrsum`.`user` AS `USER`,
  `usrsum`.`file_ios` AS `FILE_IOS`
FROM
  `sys`.`user_summary` AS `usrsum`
ORDER BY
  `usrsum`.`rows_affected` DESC
LIMIT 5;
