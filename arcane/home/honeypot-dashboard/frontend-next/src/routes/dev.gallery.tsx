import { createFileRoute } from '@tanstack/react-router'
import { useState } from 'react'
import { Avatar, AvatarFallback } from '../components/ui/avatar'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '../components/ui/dropdown-menu'
import { Input } from '../components/ui/input'
import { Separator } from '../components/ui/separator'
import { Sheet, SheetContent, SheetTitle } from '../components/ui/sheet'
import { SidebarGroup, SidebarGroupLabel, SidebarMenu, SidebarMenuItem } from '../components/ui/sidebar'
import { Skeleton } from '../components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '../components/ui/tooltip'

export const Route = createFileRoute('/dev/gallery')({ component: Gallery })

function Gallery() {
  const [open, setOpen] = useState(false)
  return <div className="space-y-6 p-6">
    <h1>Component gallery</h1>
    <Card><CardHeader><CardTitle>Card</CardTitle></CardHeader><CardContent>Card content <Badge>Badge</Badge></CardContent></Card>
    <Button onClick={() => setOpen(true)}>Button / open Sheet</Button>
    <Sheet open={open} onOpenChange={setOpen}><SheetContent><SheetTitle>Sheet</SheetTitle>Sheet content</SheetContent></Sheet>
    <DropdownMenu><DropdownMenuTrigger asChild><Button variant="outline">Dropdown menu</Button></DropdownMenuTrigger><DropdownMenuContent><DropdownMenuItem>Item</DropdownMenuItem></DropdownMenuContent></DropdownMenu>
    <TooltipProvider><Tooltip><TooltipTrigger asChild><Button variant="ghost">Tooltip</Button></TooltipTrigger><TooltipContent>Tooltip content</TooltipContent></Tooltip></TooltipProvider>
    <Avatar><AvatarFallback>A</AvatarFallback></Avatar><Separator /><Input aria-label="Input" placeholder="Input" /><Skeleton className="h-6 w-24" />
    <Tabs defaultValue="one"><TabsList><TabsTrigger value="one">One</TabsTrigger><TabsTrigger value="two">Two</TabsTrigger></TabsList><TabsContent value="one">First panel</TabsContent><TabsContent value="two">Second panel</TabsContent></Tabs>
    <Table><TableHeader><TableRow><TableHead>Column</TableHead></TableRow></TableHeader><TableBody><TableRow><TableCell>Cell</TableCell></TableRow></TableBody></Table>
    <SidebarGroup><SidebarGroupLabel>Sidebar</SidebarGroupLabel><SidebarMenu><SidebarMenuItem>Menu item</SidebarMenuItem></SidebarMenu></SidebarGroup>
  </div>
}
