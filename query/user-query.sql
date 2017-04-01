SELECT
  CONCAT(`usr`.`USER`, '@', `usr`.`HOST`) AS `GRANTEE`
FROM
  `mysql`.`user` AS `usr`
WHERE
  TRIM(`usr`.`USER`) = ''
OR
  `usr`.`USER` IS NULL;