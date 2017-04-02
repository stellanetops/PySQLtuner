SELECT
  CONCAT(`usr`.`USER`, '@', `usr`.`HOST`) AS `GRANTEE`
FROM
  `mysql`.`user` AS `usr`
WHERE
  `usr`.`:password_column` = ''
  OR
    `usr`.`:password_column` IS NULL;